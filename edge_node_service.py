from concurrent.futures.thread import ThreadPoolExecutor

import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb
import grpc
import edge_node

import logging


class EdgeService(wbgrpc.EdgeNodeServicer):
    def __init__(self):
        self.edge_node = edge_node.EdgeNode()


    def Execute(self, request: wb.Transaction, context):

        print("Request received: %s" %request)
        h1 = self.edge_node.get_txn_from_client(request)
        return h1

    def GetPhase2Hash(self, request, context):
        print("Received LogHash for phase2 response: %s" %request)
        return wb.Hash2(TxnHash=bytes("hash2".encode('utf-8')))

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