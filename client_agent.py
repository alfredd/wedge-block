from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

import pickle
import merklelib
import hashlib
import time
import multiprocessing as mp
import threading

from block_validator import BlockValidator

import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb

private_key = ECC.import_key(open('privatekey.der', 'rb').read())
trusted_public_key = ECC.import_key(open('publickey.der', 'rb').read())

signer = DSS.new(private_key, 'fips-186-3')
verifier = DSS.new(trusted_public_key, 'fips-186-3')


def hash_func(value):
    return hashlib.sha256(value).hexdigest()


def make_transaction(key, val, seq) -> wb.Transaction:
    global signer
    if type(key) is str and type(val) is str:
        key = str.encode(key)
        val = str.encode(val)
    txn_content = wb.RWSet(type=wb.TxnType.RW, key=key, val=val)
    txn_content_hash = SHA256.new(txn_content.SerializeToString())
    txn_signature = signer.sign(txn_content_hash)
    return wb.Transaction(rw=txn_content, signature=txn_signature, sequenceNumber=seq)

def verify_response(hash1_response: wb.Hash1Response, original_transaction: wb.Transaction):
    ##### for hash1_response in hash1_response_batch.content:
    # verify the signature is correct
    global verifier

    sig_verify_start = time.perf_counter()
    
    hash1 = hash1_response.h1
    response_signature = hash1_response.signature
    received_response_hash = SHA256.new(hash1.SerializeToString())
    try:
        verifier.verify(received_response_hash, response_signature)
    except ValueError:
        return (False, 0, 0)
    sig_verify_time = time.perf_counter() - sig_verify_start

    # verify the merkle proof is correct
    tree_inclusion_verify_start = time.perf_counter()

    merkle_proof = pickle.loads(hash1.merkleProof)  # deserialize
    data = (original_transaction.rw.key, original_transaction.rw.val, original_transaction.sequenceNumber)  # data to be verified
    if not merklelib.verify_leaf_inclusion(data, merkle_proof, hash_func, hash1.merkleRoot):
        return (False, 0, 0)
    tree_inclusion_verify_time = time.perf_counter() - tree_inclusion_verify_start
    
    return (True, sig_verify_time, tree_inclusion_verify_time)


class ClientAgent:
    def __init__(self):
        self.stub = None
        self.bc_block_validator = BlockValidator()
        self.hash2_checking_interval = 5

    def _check_hash2(self, hash1: wb.Hash1):
        logHash = wb.LogHash(logIndex=hash1.logIndex, merkleRoot=hash1.merkleRoot.encode())
        hash2 = self.stub.GetPhase2Hash(logHash)
        if hash2.status is wb.Hash2Status.INVALID:
            # raise Exception
            raise Exception("logHash ", logHash, " is invalid")

        while hash2.status is not wb.Hash2Status.VALID:
            hash2 = self.stub.GetPhase2Hash(logHash)
            time.sleep(self.hash2_checking_interval)
        self.bc_block_validator.thread_safe_verify(hash2.TxnHash, hash1.merkleRoot, hash1.logIndex)

    def run(self, stub: wbgrpc.EdgeNodeStub):
        pool = mp.get_context('spawn').Pool(mp.cpu_count())
        self.stub = stub
        start_t = time.perf_counter()

        batch_size = 10000
        
        # transaction_batch = generate_transaction_batch(batch_size)
        
        result_objects = []
        for i in range(batch_size):
            result_objects.append(pool.apply_async(make_transaction, args=(i.to_bytes(64, 'big'), i.to_bytes(1024, 'big'),i)))
        workload = [r.get() for r in result_objects]
        transaction_batch = wb.TransactionBatch(content=workload)

        request_generated_t = time.perf_counter()
        print("workload generated using: ", round(request_generated_t - start_t, 4))

        received_unique_hash1 = dict()

        result_objects = []
        # send #batch_size many transactions to the edge node
        request_sent_t = time.perf_counter()
        first_response_received_t = None
        avg_round_trip_time = 0
        sequenceNumber = 0
        for hash1_response in self.stub.ExecuteBatch(transaction_batch):
            if first_response_received_t == None:
                first_response_received_t = time.perf_counter()
            avg_round_trip_time += time.perf_counter() - request_sent_t
            result_objects.append(pool.apply_async(verify_response, args=(hash1_response, workload[sequenceNumber])))
            # extract unique hash1s for hash2 queries
            # several hash1s might have been placed in the same bc txn thus sharing same hash2
            if hash1_response.h1.logIndex not in received_unique_hash1:
                received_unique_hash1[hash1_response.h1.logIndex] = hash1_response.h1
            sequenceNumber += 1
        last_response_received_t = time.perf_counter()

        verification_results = [r.get() for r in result_objects]
        pool.close()
        pool.join()

        # check if all verification passed and accumulate performance measurements
        total_sig_verify_t = 0
        total_tree_inclusion_verify_t = 0
        for v_result in verification_results:
            try:
                assert v_result[0]
            except AssertionError:
                print("Verification Failed")
            total_sig_verify_t += v_result[1]
            total_tree_inclusion_verify_t += v_result[2]

        end_t = time.perf_counter()

        print("First txn/response RTT (sent out -> received): ", round(first_response_received_t - request_sent_t, 4))
        print("Last  txn/response RTT (sent out -> received): ", round(last_response_received_t - request_sent_t, 4))

        print("Average time (each txn) on signature verification: ", round(total_sig_verify_t / batch_size, 4))
        print("Average time (each txn) on merkle proof verification: ", round(total_tree_inclusion_verify_t / batch_size, 4))

        print("Total phase1 latency (all sent out -> all verified): ", round(end_t - request_sent_t, 4))
        print("Phase1 Throughput: ", round(batch_size/(end_t - request_sent_t),4))

        # for each unique hash1, ask server for its hash2
        hash2_verify_start = time.perf_counter()
        all_hash2_threads = []
        for k,hash1 in received_unique_hash1.items():
            thread = threading.Thread(target=self._check_hash2, args=(hash1,))
            all_hash2_threads.append(thread)
            thread.start()

        for thread in all_hash2_threads:
            thread.join()
        hash2_verify_end = time.perf_counter()
        print("Total phase2 latency (all hash2 verified): ", round(hash2_verify_end - hash2_verify_start, 4))
        return
