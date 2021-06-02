import grpc
import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb

import merklelib
import hashlib
import pickle
import threading
import time
from ropsten_connector import *
import time, ast

from ropsten_connector import RopEth


def hashfunc(value):
    return hashlib.sha256(value).hexdigest()


def send_request(stub, key, val):
    t = wb.Transaction(rw=wb.RWSet(type=wb.TxnType.RW, key=key, val=val))
    start = time.perf_counter()
    hash1 = stub.Execute(t)
    stop = time.perf_counter()
    print("Phase1, ", (stop-start))
    merkle_proof = pickle.loads(hash1.merkleProof)  # deserialize
    data = (t.rw.key, t.rw.val)  # data to be verified

    if merklelib.verify_leaf_inclusion(data, merkle_proof, hashfunc, hash1.merkleRoot):
        print("hash1 is correct for ", data)
    else:
        print("something wrong")
    print("Phase1 verification, ", (time.perf_counter()-stop))

    print("Received hash1: %s" % hash1)
    time.sleep(10)
    reth = RopEth()
    print("Checking Hash2 status")
    logHash = wb.LogHash(logIndex=hash1.logIndex, merkleRoot=hash1.merkleRoot)
    hash2 = stub.GetPhase2Hash(logHash)

    reth = RopEth()
    print("Checking Hash2 status")
    logHash = wb.LogHash(logIndex=hash1.logIndex, merkleRoot=hash1.merkleRoot.encode())
    hash2 = stub.GetPhase2Hash(logHash)
    if hash2.status is wb.Hash2Status.INVALID:
        # raise Exception
        print("logHash ", logHash, " is invalid")

    while hash2.status is not wb.Hash2Status.VALID:
        hash2 = stub.GetPhase2Hash(logHash)
        time.sleep(10)
    message = reth.getInputMessageForTxn(hash2.TxnHash)

    print(message)

    # (merkleroot, logindex) = ast.literal_eval(message)
    # assert merkleroot == hash1.merkleRoot
    # assert logindex == hash1.logIndex

    # message = reth.getInputMessageForTxn(hash2.TxnHash)
    (merkleroot, logindex)= ast.literal_eval(message)
    assert merkleroot == hash1.merkleRoot
    assert logindex==hash1.logIndex

def run():
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.
    print("Running client")
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = wbgrpc.EdgeNodeStub(channel)

        max_threads = 1
        all_threads = []
        arg_list = [(stub,"x","1"),(stub,"y","2"),(stub,"z","3"),(stub,"a","0"),(stub,"b","1"),(stub,"c","3")]

        # assert len(arg_list) == max_threads

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