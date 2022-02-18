from Crypto.Hash import SHA256

import pickle
import merklelib
import hashlib
import time
import multiprocessing as mp
import random

from credential_tools import signer, verifier, verify_eth_msg_sig


import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb


def hash_func(value):
    return hashlib.sha256(value).hexdigest()


def verify_response(hash1_response: wb.Hash1Response):
    # verify the signature is correct
    sig_verify_start = time.perf_counter()

    hash1 = hash1_response.h1
    response_signature = hash1_response.responseSignature
    received_response_hash = SHA256.new(hash1.SerializeToString())
    try:
        verifier.verify(received_response_hash, response_signature)
    except ValueError:
        return False, 0, 0
    sig_verify_time = time.perf_counter() - sig_verify_start

    # verify eth msg signature is correct
    eth_msg_verified = verify_eth_msg_sig(hash1.logIndex, hash1.merkleRoot, hash1_response.ethMsgSignature)
    if not eth_msg_verified:
        return False, 0, 0

    # verify the merkle proof is correct
    tree_inclusion_verify_start = time.perf_counter()

    merkle_proof = pickle.loads(hash1.merkleProof)  # deserialize
    # data to be verified
    data = (hash1.rw.key, hash1.rw.val, hash1.sequenceNumber)
    if not merklelib.verify_leaf_inclusion(data, merkle_proof, hash_func, hash1.merkleRoot):
        return False, 0, 0
    tree_inclusion_verify_time = time.perf_counter() - tree_inclusion_verify_start

    return True, sig_verify_time, tree_inclusion_verify_time


class AuditorAgent:
    def __init__(self):
        self.stub = None

    def send_query(self, query_size):
        pool = mp.get_context('spawn').Pool(mp.cpu_count())

        keys = []
        total_key_number_at_edge = 10000
        for i in random.sample(range(total_key_number_at_edge), query_size):
            keys.append(i.to_bytes(64, 'big'))

        query_content_hash = SHA256.new(str(keys).encode())
        query_signature = signer.sign(query_content_hash)
        request = wb.QueryBatch(keys=keys, signature=query_signature)

        request_sent_t = time.perf_counter()

        all_hash1_response = []
        for hash1_response in self.stub.AnswerQuery(request):
            # reading the query results without verifying them yet
            # print(hash1_response.h1.rw.val, hash1_response.h1.sequenceNumber)
            all_hash1_response.append(hash1_response)

        after_read_before_verify_t = time.perf_counter()

        result_objects = []
        for hash1_response in all_hash1_response:
            if hash1_response is None:
                continue
            result_objects.append(pool.apply_async(verify_response, args=(hash1_response,)))

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
        total_txn_count = query_size

        print("Avg time (per txn) on signature verification: ",
              round(total_sig_verify_t / total_txn_count, 4))
        print("Avg time (per txn) on merkle proof verification: ",
              round(total_tree_inclusion_verify_t / total_txn_count, 4))

        print("Total reading latency (sent out queries -> all responses read): ",
              round(after_read_before_verify_t - request_sent_t, 4))
        print("Total verifying latency (all responses read -> all verified): ",
              round(end_t - after_read_before_verify_t, 4))
        print("Total latency (sent out queries -> all verified): ",
              round(end_t - request_sent_t, 4))

        print("Throughput: (queries per sec)",
              round(total_txn_count / (end_t - request_sent_t), 4))

    def send_audit_request(self, log_indexes):
        pool = mp.get_context('spawn').Pool(mp.cpu_count())

        query_content_hash = SHA256.new(str(log_indexes).encode())
        query_signature = signer.sign(query_content_hash)
        request = wb.AuditRequest(logIndexes=log_indexes, signature=query_signature)

        request_sent_t = time.perf_counter()

        all_hash1_response = []
        for hash1_response in self.stub.AnswerFullLogAudit(request):
            # reading the query results without verifying them yet
            # print(hash1_response.h1.rw.val, hash1_response.h1.sequenceNumber)
            all_hash1_response.append(hash1_response)

        after_read_before_verify_t = time.perf_counter()

        result_objects = []
        for hash1_response in all_hash1_response:
            if hash1_response is None:
                continue
            result_objects.append(pool.apply_async(verify_response, args=(hash1_response,)))

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
        total_txn_count = len(verification_results)

        print("Avg time (per txn) on signature verification: ",
              round(total_sig_verify_t / total_txn_count, 4))
        print("Avg time (per txn) on merkle proof verification: ",
              round(total_tree_inclusion_verify_t / total_txn_count, 4))

        print("Total reading latency (sent out queries -> all responses read): ",
              round(after_read_before_verify_t - request_sent_t, 4))
        print("Total verifying latency (all responses read -> all verified): ",
              round(end_t - after_read_before_verify_t, 4))
        print("Total latency (sent out queries -> all verified): ",
              round(end_t - request_sent_t, 4))

        print("Throughput: (queries per sec)",
              round(total_txn_count / (end_t - request_sent_t), 4))

    def run(self, stub: wbgrpc.EdgeNodeStub):
        self.stub = stub

        log_indexes_to_query = list(range(10))
        self.send_audit_request(log_indexes_to_query)

        # query_size = 2000
        # self.send_query(query_size)
