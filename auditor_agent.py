from Crypto.Hash import SHA256

import pickle
import merklelib
import hashlib
import time
import multiprocessing as mp
import random

from credential_tools import signer, verify_hash1_response
from keccakTest_contract import keccakTestContract


import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb


class AuditorAgent:
    def __init__(self):
        self.stub = None
        self.keccak_test_contract = keccakTestContract()

    def send_query(self, query_size, is_lite_version=False, keys=[]):
        pool = mp.get_context('spawn').Pool(mp.cpu_count())

        query_content_hash = SHA256.new(str(keys).encode())
        query_signature = signer.sign(query_content_hash)
        request = wb.QueryBatch(keys=keys, isLiteVersion=is_lite_version, signature=query_signature)

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
            result_objects.append(pool.apply_async(verify_hash1_response,
                                                   args=(hash1_response,),
                                                   kwds={'is_lite_version': is_lite_version}))

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
                ## self.invoke_punishment("the faulty hash1 response")
            total_sig_verify_t += v_result[1]
            total_tree_inclusion_verify_t += v_result[2]

        end_t = time.perf_counter()
        total_txn_count = query_size
        
        '''
        print("Avg time (per txn) on signature verification: ",
              round(total_sig_verify_t / total_txn_count, 4))
        print("Avg time (per txn) on merkle proof verification: ",
              round(total_tree_inclusion_verify_t / total_txn_count, 4))
        '''

        print("Total reading latency (sent out queries -> all responses read): ",
              round(after_read_before_verify_t - request_sent_t, 4))
        print("Total verifying latency (all responses read -> all verified): ",
              round(end_t - after_read_before_verify_t, 4))
        print("Total latency (sent out queries -> all verified): ",
              round(end_t - request_sent_t, 4))

        print("Throughput: (queries per sec)",
              round(total_txn_count / (end_t - request_sent_t), 4))

    def send_audit_request(self, log_indexes, is_lite_version=False):
        pool = mp.get_context('spawn').Pool(mp.cpu_count())

        query_content_hash = SHA256.new(str(log_indexes).encode())
        query_signature = signer.sign(query_content_hash)
        request = wb.AuditRequest(logIndexes=log_indexes, isLiteVersion=is_lite_version, signature=query_signature)

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
            result_objects.append(pool.apply_async(verify_hash1_response,
                                                   args=(hash1_response,),
                                                   kwds={'is_lite_version': is_lite_version}))

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

        '''
        print("Avg time (per txn) on signature verification: ",
              round(total_sig_verify_t / total_txn_count, 4))
        print("Avg time (per txn) on merkle proof verification: ",
              round(total_tree_inclusion_verify_t / total_txn_count, 4))
        '''
        
        print("Total reading latency (sent out queries -> all responses read): ",
              round(after_read_before_verify_t - request_sent_t, 4))
        print("Total verifying latency (all responses read -> all verified): ",
              round(end_t - after_read_before_verify_t, 4))
        print("Total latency (sent out queries -> all verified): ",
              round(end_t - request_sent_t, 4))

        print("Throughput: (queries per sec)",
              round(total_txn_count / (end_t - request_sent_t), 4))


    def invoke_punishment(self, hash1_response):
        hash1 = hash1_response.h1
        # print(hash1.logIndex)
        # print(hash1.merkleRoot)
        # print(hash1.merkleProofPath)
        # print(hash1.merkleProofDir)
        # print(hash1.rawTxnStr)
        # print(hash1_response.ethMsgSignature)
        self.keccak_test_contract.invokePunishment(hash1.logIndex, hash1.merkleRoot,
                                                   hash1.merkleProofPath, hash1.merkleProofDir,
                                                   hash1.rawTxnStr, hash1_response.ethMsgSignature)


    def run(self, stub: wbgrpc.EdgeNodeStub):
        self.stub = stub
        total_key_number_at_edge = 100 * 10000
        query_size = 50000

        keys = []
        # This must be consistent with how many keys are stored at edge
        # BAD hard-coding just for experiment purposes.
        for i in random.sample(range(total_key_number_at_edge), query_size):
            keys.append(i.to_bytes(64, 'big'))

        # warm up
        self.send_query(query_size, is_lite_version=using_lite_version, keys=keys)
        
        for full_audit in [False, True]:
            for using_lite_version in [False, True]:
                print("full_audit: ", full_audit, "lite_version: ", using_lite_version)
                if full_audit:
                    log_indexes_to_query = list(range(20))
                    self.send_audit_request(log_indexes_to_query, is_lite_version=using_lite_version)
                else:
                    self.send_query(query_size, is_lite_version=using_lite_version, keys=keys)
                print()
