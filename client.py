from client_agent import ClientAgent

import grpc
import wedgeblock_pb2_grpc as wbgrpc


def run():
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.
    print("Running client")

    with grpc.insecure_channel('localhost:50051') as channel:
        stub = wbgrpc.EdgeNodeStub(channel)
        max_threads = 10
        ClientAgent().run(stub, max_threads)


if __name__ == '__main__':
    run()
