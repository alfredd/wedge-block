from client_agent import ClientAgent

import grpc
import wedgeblock_pb2_grpc as wbgrpc
import sys


def run(client_id: int):
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.

    # print("Running client")
    options = [('grpc.max_receive_message_length', 1024 * 1024 * 1024)]
    # with grpc.insecure_channel('10.140.83.115:50051', options=options) as channel:
    with grpc.insecure_channel('localhost:50051', options=options) as channel:
        stub = wbgrpc.EdgeNodeStub(channel)
        ClientAgent(client_id).run(stub)


if __name__ == '__main__':
    client_id = int(sys.argv[1])
    run(client_id)
