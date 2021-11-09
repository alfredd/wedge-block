from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

import pickle
import merklelib
import hashlib
import time
import multiprocessing as mp
import threading

from block_validator import BlockValidator, CallBackValidator

import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb

private_key = ECC.import_key(open('privatekey.der', 'rb').read())
trusted_public_key = ECC.import_key(open('publickey.der', 'rb').read())

signer = DSS.new(private_key, 'fips-186-3')
verifier = DSS.new(trusted_public_key, 'fips-186-3')

verification_results = []
lock = threading.Lock()

def hash_func(value):
    return hashlib.sha256(value).hexdigest()


def make_transaction(key, val) -> wb.Transaction:
    global signer
    if type(key) is str and type(val) is str:
        key = str.encode(key)
        val = str.encode(val)
    txn_content = wb.RWSet(type=wb.TxnType.RW, key=key, val=val)
    txn_content_hash = SHA256.new(txn_content.SerializeToString())
    txn_signature = signer.sign(txn_content_hash)
    return wb.Transaction(rw=txn_content, signature=txn_signature)


def generate_transaction_batch(total_number) -> wb.TransactionBatch:
    pool = mp.Pool(mp.cpu_count())
    result_objects = [pool.apply_async(make_transaction, args=(i.to_bytes(8,'big'), i.to_bytes(64,'big'))) for i in range(total_number)]
    results = [r.get() for r in result_objects]
    pool.close()
    pool.join()
    transaction_batch = wb.TransactionBatch(content=results)
    return transaction_batch


def verify_response(hash1_response: wb.Hash1Response):
    ##### for hash1_response in hash1_response_batch.content:
    # verify the signature is correct
    sig_verify_start = time.perf_counter()

    hash1 = hash1_response.h1
    response_signature = hash1_response.signature
    received_response_hash = SHA256.new(hash1.SerializeToString())
    try:
        verifier.verify(received_response_hash, response_signature)
        # print("The response is authentic.")
    except ValueError:
        # print("The response is not authentic.")
        return (False, 0, 0)

    sig_verify_time = time.perf_counter() - sig_verify_start

    # verify the merkle proof is correct
    tree_inclusion_verify_start = time.perf_counter()
    merkle_proof = pickle.loads(hash1.merkleProof)  # deserialize
    data = (hash1_response.h1.rw.key, hash1_response.h1.rw.val)  # data to be verified
    if not merklelib.verify_leaf_inclusion(data, merkle_proof, hash_func, hash1.merkleRoot):
        return (False, 0, 0)
    tree_inclusion_verify_time = time.perf_counter() - tree_inclusion_verify_start
    return (True, sig_verify_time, tree_inclusion_verify_time)


def collect_result(result):
    global verification_results
    lock.acquire()
    verification_results.append(result)
    lock.release()


class ClientAgent:
    def __init__(self):
        self.stub = None
        self.bc_block_validator = BlockValidator()
        self.hash2_checking_interval = 2
        self.performance_monitor = None

    def _check_hash2(self, hash1: wb.Hash1):
        logHash = wb.LogHash(logIndex=hash1.logIndex, merkleRoot=hash1.merkleRoot.encode())
        hash2 = self.stub.GetPhase2Hash(logHash)
        if hash2.status is wb.Hash2Status.INVALID:
            # raise Exception
            raise Exception("logHash ", logHash, " is invalid")

        while hash2.status is not wb.Hash2Status.VALID:
            hash2 = self.stub.GetPhase2Hash(logHash)
            time.sleep(self.hash2_checking_interval)
        cb = CallBackValidator()
        self.bc_block_validator.insert_to_verify(hash2.TxnHash, hash1.merkleRoot, hash1.logIndex, cb.call_back)

    def run(self, stub: wbgrpc.EdgeNodeStub):
        self.stub = stub
        start_t = time.perf_counter()

        batch_size = 10000
        transaction_batch = generate_transaction_batch(batch_size)
        request_generated_t = time.perf_counter()
        print("workload generated using: ", round(request_generated_t - start_t, 4))

        unique_hash1 = dict()

        # self.performance_monitor = ClientAgent.PerformanceMonitor()
        # self.performance_monitor.mark_start()

        pool2 = mp.Pool(mp.cpu_count())
        # send #batch_size many transactions to the edge node
        for hash1_response in self.stub.ExecuteBatch(transaction_batch):
            hash1 = hash1_response.h1
            if hash1.merkleRoot not in unique_hash1:
                unique_hash1[hash1.merkleRoot] = hash1
            pool2.apply_async(verify_response, args=(hash1_response,), callback=collect_result)

        end_t = time.perf_counter()

        pool2.close()
        pool2.join()

        total_sig_verify_t = 0
        total_tree_inclusion_verify_t = 0

        for v_result in verification_results:
            try:
                assert v_result[0]
            except AssertionError:
                print("Verification Failed")

            total_sig_verify_t += v_result[1]
            total_tree_inclusion_verify_t += v_result[2]

        print("Total time on signature verification: ", round(total_sig_verify_t, 4))
        print("Average time on signature verification: ", round(total_sig_verify_t / batch_size, 4))
        print("Total time on merkle proof verification: ", round(total_tree_inclusion_verify_t, 4))
        print("Average time on merkle proof verification: ", round(total_tree_inclusion_verify_t / batch_size, 4))

        print("Total phase1 latency: ", round(end_t - request_generated_t, 4))
        print("Phase1 Throughput: ", round(batch_size/(end_t - request_generated_t),4))
        print("done")

        # all_hash2_threads = []
        # for hash1 in unique_hash1.values():
        #     thread = threading.Thread(target=self._check_hash2, args=(hash1,))
        #     all_hash2_threads.append(thread)
        #     thread.start()
        #
        # for thread in all_hash2_threads:
        #     thread.join()
        #     self.performance_monitor.mark_phase2_complete()

        return
