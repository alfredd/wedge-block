import grpc
import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb
import logging


def run():
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.
    print("Running client")
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = wbgrpc.EdgeNodeStub(channel)
        t = wb.Transaction(rw=wb.RWSet(type=wb.TxnType.RW, key="k", val="v"))
        print("Sending t: %s" %t)
        hash1 = stub.Execute(t)
        print("Received hash1: %s" %hash1)

        hash2 = stub.GetPhase2Hash(wb.LogHash(logIndex=hash1.logIndex))
        print("Received hash2: %s" %hash2)
if __name__ == '__main__':
    run()