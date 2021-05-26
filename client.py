import logging

import grpc
import wedgeblock_pb2
import wedgeblock_pb2_grpc


def edge_execute(stub):
    rwset = wedgeblock_pb2.RWSet(type=wedgeblock_pb2.TxnType.RW, key="x", val="1")
    txn = wedgeblock_pb2.Transaction(rw = rwset)
    proof = stub.Execute(txn)
    print(proof)


def run():
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = wedgeblock_pb2_grpc.EdgeNodeStub(channel)
        print("-------------- Execute --------------")
        edge_execute(stub)


if __name__ == '__main__':
    logging.basicConfig()
    run()