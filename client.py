import grpc
import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb

import merklelib
import hashlib
import pickle
import threading


def hashfunc(value):
    return hashlib.sha256(value).hexdigest()


def send_request(stub, key, val):
    t = wb.Transaction(rw=wb.RWSet(type=wb.TxnType.RW, key=key, val=val))
    hash1 = stub.Execute(t)

    merkle_proof = pickle.loads(hash1.merkleProof)  # deserialize
    data = (t.rw.key, t.rw.val)  # data to be verified

    if merklelib.verify_leaf_inclusion(data, merkle_proof, hashfunc, hash1.merkleRoot):
        print("hash1 is correct for ", data)
    else:
        print("something wrong")

    print("Received hash1: %s" % hash1)


def run():
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.
    print("Running client")
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = wbgrpc.EdgeNodeStub(channel)

        max_threads = 6
        all_threads = []
        arg_list = [(stub,"x","1"),(stub,"y","2"),(stub,"z","3"),(stub,"a","0"),(stub,"b","1"),(stub,"c","3")]

        assert len(arg_list) == max_threads

        for i in range(max_threads):
            thread = threading.Thread(target=send_request, args=arg_list[i])
            all_threads.append(thread)
            thread.start()

        for thread in all_threads:
            thread.join()
        #
        # hash2 = stub.GetPhase2Hash(wb.LogHash(logIndex=hash1.logIndex))
        # print("Received hash2: %s" %hash2)
if __name__ == '__main__':
    run()