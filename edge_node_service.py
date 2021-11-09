import time
from concurrent.futures.thread import ThreadPoolExecutor

import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb
import grpc
import edge_node

import logging

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
        # verify all signatures are correct
        batch_verify_avg = 0
        batch_time_avg = 0
        batch_signing_avg = 0

        for batch_n in range(len(request.content)//self.batch_size + 1):
            batch = request.content[batch_n*self.batch_size:(batch_n+1)*self.batch_size]
            if (len(batch) == 0):
                batch_n -= 1
                break

            batch_begin = time.perf_counter()

            # verify txn in this batch
            for txn in batch:
                txn_hash = SHA256.new(txn.rw.SerializeToString())
                self.verifier.verify(txn_hash, txn.signature)
            batch_verify_avg += time.perf_counter() - batch_begin

            # process the txn batch to get h1 batch
            h1_result = self.edge_node.process_txn_batch(batch)

            # signing the h1 batch
            signing_start = time.perf_counter()
            batch_response = []
            for h1 in h1_result:
                response_content_hash = SHA256.new(h1.SerializeToString())
                response_signature = self.signer.sign(response_content_hash)
                # response_signature = None
                response = wb.Hash1Response(h1=h1, signature=response_signature)
                batch_response.append(response)
            # batch_response = wb.Hash1ResponseBatch(content=batch_response)

            batch_signing_avg += time.perf_counter() - signing_start
            batch_time_avg += time.perf_counter() - batch_begin

            for response in batch_response:
                yield response

        print("Avg time per batch (txn_verify): ", round(batch_verify_avg/(batch_n + 1),4))
        print(self.edge_node.analyser.get_avg_record())
        print("Avg time per batch (h1_sign): ", round(batch_signing_avg / (batch_n + 1),4))
        print("Avg time per batch (total): ", round(batch_time_avg/(batch_n + 1),4))
        print("ExecuteBatch Completed\n")


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