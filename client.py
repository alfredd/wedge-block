import grpc
import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb

import merklelib
import hashlib
import pickle
import threading

from block_validator import BlockValidator
import time

phase1_latency = 0
phase2_latency = 0
latency_update_lock = threading.Lock()


class CallBackValidator():
    def call_back(self, txnHash, expected, actual):
        # print("checking callback for txnHash %s." %txnHash)
        assert expected[0]==actual[0]
        assert expected[1]==actual[1]

def hashfunc(value):
    return hashlib.sha256(value).hexdigest()


def send_request(stub, key, val, bv:BlockValidator):
    global phase1_latency
    global phase2_latency
    global latency_update_lock
    t = wb.Transaction(rw=wb.RWSet(type=wb.TxnType.RW, key=key, val=val))
    start = time.perf_counter()
    hash1 = stub.Execute(t)
    stop = time.perf_counter()

    latency_update_lock.acquire()
    phase1_latency += stop-start
    print("Phase1, ", (stop-start))
    latency_update_lock.release()

    merkle_proof = pickle.loads(hash1.merkleProof)  # deserialize
    data = (t.rw.key, t.rw.val)  # data to be verified

    assert merklelib.verify_leaf_inclusion(data, merkle_proof, hashfunc, hash1.merkleRoot)
    # print("Phase1 verification, ", (time.perf_counter()-stop))


    # print("Checking Hash2 status")
    logHash = wb.LogHash(logIndex=hash1.logIndex, merkleRoot=hash1.merkleRoot.encode())
    hash2 = stub.GetPhase2Hash(logHash)
    if hash2.status is wb.Hash2Status.INVALID:
        # raise Exception
        print("logHash ", logHash, " is invalid")

    while hash2.status is not wb.Hash2Status.VALID:
        hash2 = stub.GetPhase2Hash(logHash)
        time.sleep(2)
    cb = CallBackValidator()
    bv.insert_to_verify(hash2.TxnHash, hash1.merkleRoot, hash1.logIndex,cb.call_back)

    latency_update_lock.acquire()
    phase2_latency += time.perf_counter() - start
    print("Phase2 ", time.perf_counter() - start)
    latency_update_lock.release()


def run():
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.
    print("Running client")
    block_validator = BlockValidator()
    precision = 4

    with grpc.insecure_channel('localhost:50051') as channel:
        stub = wbgrpc.EdgeNodeStub(channel)

        max_threads = 10
        all_threads = []
        # arg_list = [(stub,"x","1"),(stub,"y","2"),(stub,"z","3"),(stub,"a","0"),(stub,"b","1"),(stub,"c","3")]
        # assert len(arg_list) == max_threads

        for i in range(max_threads):
            thread = threading.Thread(target=send_request, args=(stub, str(i), str(i*i), block_validator))
            all_threads.append(thread)
            thread.start()

        for thread in all_threads:
            thread.join()
        print('{} & {}'.format(round(phase1_latency/max_threads, precision),
                               round(phase2_latency/max_threads, precision)))
        #
        # hash2 = stub.GetPhase2Hash(wb.LogHash(logIndex=hash1.logIndex))
        # print("Received hash2: %s" %hash2)
if __name__ == '__main__':
    run()