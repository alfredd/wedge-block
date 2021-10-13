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

        self.trusted_public_key = ECC.import_key(open('publickey.der', 'rb').read())
        self.verifier = DSS.new(self.trusted_public_key, 'fips-186-3')

        private_key = ECC.import_key(open('privatekey.der', 'rb').read())
        self.signer = DSS.new(private_key, 'fips-186-3')

    def Execute(self, request: wb.Transaction, context):
        # print("Request received: %s" %request)
        received_content = pickle.dumps(request.rw)
        signature = request.signature

        received_content_hash = SHA256.new(received_content)
        try:
            self.verifier.verify(received_content_hash, signature)
            # print("The request is authentic.")
        except ValueError:
            print("The request is not authentic.")

        h1 = self.edge_node.get_txn_from_client(request)

        response_content_bytes = pickle.dumps(h1)
        response_content_hash = SHA256.new(response_content_bytes)
        response_signature = self.signer.sign(response_content_hash)

        response = wb.Hash1Response(h1 = h1, signature = response_signature)

        return response

    def GetPhase2Hash(self, request, context):
        if not self.edge_node.is_valid_index(request.logIndex):
            return wb.Hash2(status=wb.Hash2Status.INVALID)
        h2 = self.edge_node.reply_h2_to_client(request)
        if h2 is not None:
            return wb.Hash2(TxnHash=h2, status=wb.Hash2Status.VALID)
        return wb.Hash2(status=wb.Hash2Status.NOT_READY)


def serve():
    server = grpc.server(ThreadPoolExecutor(max_workers=500))
    wbgrpc.add_EdgeNodeServicer_to_server(
        EdgeService(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    logging.basicConfig()
    serve()