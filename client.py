import grpc
import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb

import sys
import merklelib
import hashlib
import pickle


def hashfunc(value):
    return hashlib.sha256(value).hexdigest()

def run():
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.
    print("Running client")
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = wbgrpc.EdgeNodeStub(channel)
        t = wb.Transaction(rw=wb.RWSet(type=wb.TxnType.RW, key=sys.argv[1], val=sys.argv[2]))
        print("Sending t: %s" %t)
        hash1 = stub.Execute(t)

        merkle_proof = pickle.loads(hash1.merkleProof) # deserialize
        data = (hash1.rw.key, hash1.rw.val)

        if merklelib.verify_leaf_inclusion(data, merkle_proof, hashfunc, hash1.merkleRoot):
            print("hash1 is correct")
        else:
            print("something wrong")

        print("Received hash1: %s" %hash1)

        hash2 = stub.GetPhase2Hash(wb.LogHash(logIndex=hash1.logIndex))
        print("Received hash2: %s" %hash2)
if __name__ == '__main__':
    run()