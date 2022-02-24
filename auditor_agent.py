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

    def send_query(self, query_size, keys=[]):
        pool = mp.get_context('spawn').Pool(mp.cpu_count())

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
            result_objects.append(pool.apply_async(verify_hash1_response,
                                                   args=(hash1_response,)))

        verification_results = [r.get() for r in result_objects]
        pool.close()
        pool.join()

        # check if all verification passed
        for i in range(len(verification_results)):
            if verification_results[i]:
            # if not verification_results[i]:
                print("Verification Failed")
                self.invoke_punishment(all_hash1_response[i])
                break

        end_t = time.perf_counter()
        total_txn_count = query_size

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
            result_objects.append(pool.apply_async(verify_hash1_response,
                                                   args=(hash1_response,)))

        verification_results = [r.get() for r in result_objects]
        pool.close()
        pool.join()

        # check if all verification passed
        for i in range(len(verification_results)):
            if not verification_results[i]:
                print("Verification Failed")
                self.invoke_punishment(all_hash1_response[i])
                break

        end_t = time.perf_counter()
        total_txn_count = len(verification_results)
        
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
        txid = self.keccak_test_contract.invokePunishment(
            hash1.logIndex, hash1.merkleRoot, hash1.merkleProofPath,
            hash1.merkleProofDir, hash1.rawTxnStr, hash1_response.ethMsgSignature)

        response = self.keccak_test_contract.getTransactionReceipt(txid)
        print(response)


    def run(self, stub: wbgrpc.EdgeNodeStub):
        self.stub = stub
        total_key_number_at_edge = 1 # 100 * 10000
        query_size = 1 # 50000

        keys = []
        # This must be consistent with how many keys are stored at edge
        # BAD hard-coding just for experiment purposes.
        for i in random.sample(range(total_key_number_at_edge), query_size):
            keys.append(i.to_bytes(64, 'big'))

        # warm up. first request always have a low throughput for reason idk
        self.send_query(query_size, keys=keys)

        log_indexes_to_query = list(range(20))
        self.send_audit_request(log_indexes_to_query)

        self.send_query(query_size, keys=keys)
        print()
