import time
from concurrent.futures.thread import ThreadPoolExecutor

import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb
import grpc
import edge_node

import logging

import pickle
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

class EdgeService(wbgrpc.EdgeNodeServicer):
    def __init__(self):
        self.edge_node = edge_node.EdgeNode()
        self.batch_size = 1000

        self.trusted_public_key = ECC.import_key(open('publickey.der', 'rb').read())
        self.verifier = DSS.new(self.trusted_public_key, 'fips-186-3')

        private_key = ECC.import_key(open('privatekey.der', 'rb').read())
        self.signer = DSS.new(private_key, 'fips-186-3')

    def Execute(self, request: wb.Transaction, context):
        raise NotImplementedError

    def ExecuteBatch(self, request: [(wb.Transaction)], context):
        # to verify one incoming transaction, do
        #   txn_content = pickle.dumps(txn.rw)
        #   signature = txn.signature
        #   txn_hash = SHA256.new(txn_content)
        #   self.verifier.verify(txn_hash, signature)
        chunk_size = self.batch_size
        for chunk_n in range(len(request.content)//chunk_size + 1):
            chunk = request.content[chunk_n*chunk_size:(chunk_n+1)*chunk_size]
            chunk_response = []
            # start = time.perf_counter()
            for h1 in self.edge_node.process_txn_batch(chunk):
                # response_content_bytes = pickle.dumps(h1)
                # response_content_hash = SHA256.new(response_content_bytes)
                # response_signature = self.signer.sign(response_content_hash)
                response_signature = None
                response = wb.Hash1Response(h1=h1, signature=response_signature)
                chunk_response.append(response)
            response_batch = wb.Hash1ResponseBatch(content=chunk_response)
            # print("response_batch generated using", time.perf_counter() - start)
            yield response_batch
        print("ExecuteBatch Completed")


    def GetPhase2Hash(self, request: wb.LogHash, context):
        if not self.edge_node.entry_exist_at_index(request.logIndex):
            return wb.Hash2(status=wb.Hash2Status.INVALID)
        h2 = self.edge_node.get_h2_at_index(request.logIndex)
        if h2 is not None:
            return wb.Hash2(TxnHash=h2, status=wb.Hash2Status.VALID)
        return wb.Hash2(status=wb.Hash2Status.NOT_READY)


def serve():
    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    wbgrpc.add_EdgeNodeServicer_to_server(
        EdgeService(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    logging.basicConfig()
    serve()