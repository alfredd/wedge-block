from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

import threading
import pickle
import merklelib
import hashlib
import time
import os
from statistics import mean

from block_validator import BlockValidator, CallBackValidator

import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb


def hash_func(value):
    return hashlib.sha256(value).hexdigest()


class ClientAgent:
    def __init__(self):
        self._init_signer()
        self._init_verifier()
        self.stub = None
        self.bc_block_validator = BlockValidator()
        self.hash2_checking_interval = 2
        self.performance_monitor = None

    def _init_signer(self):
        private_key = ECC.import_key(open('privatekey.der', 'rb').read())
        self.signer = DSS.new(private_key, 'fips-186-3')

    def _init_verifier(self):
        trusted_public_key = ECC.import_key(open('publickey.der', 'rb').read())
        self.verifier = DSS.new(trusted_public_key, 'fips-186-3')

    def _sign_request(self, request_content: wb.RWSet):
        txn_content_bytes = pickle.dumps(request_content)
        txn_content_hash = SHA256.new(txn_content_bytes)
        txn_signature = self.signer.sign(txn_content_hash)
        return txn_signature

    def _verify_response(self, hash1_response: wb.Hash1Response):
        hash1 = hash1_response.h1
        received_response = pickle.dumps(hash1)
        response_signature = hash1_response.signature
        received_response_hash = SHA256.new(received_response)
        try:
            self.verifier.verify(received_response_hash, response_signature)
            # print("The response is authentic.")
        except ValueError:
            print("The response is not authentic.")

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

    def _make_transaction(self, key, val) -> wb.Transaction:
        if type(key) is str and type(val) is str:
            key = str.encode(key)
            val = str.encode(val)
        txn_content = wb.RWSet(type=wb.TxnType.RW, key=key, val=val)
        # txn_signature = self._sign_request(txn_content)
        txn_signature = None
        return wb.Transaction(rw=txn_content, signature=txn_signature)

    def _generate_transaction_batch(self, total_number) -> wb.TransactionBatch:
        transaction_batch = wb.TransactionBatch()
        for i in range(total_number):
            t = self._make_transaction(i.to_bytes(8,'big'), i.to_bytes(8,'big'))
            transaction_batch.content.append(t)
        return transaction_batch

    def run(self, stub: wbgrpc.EdgeNodeStub):
        self.stub = stub

        batch_size = 10000
        transaction_batch = self._generate_transaction_batch(batch_size)
        print("finished generating batch")
        collected_hash1 = set()
        hash1_list = []

        self.performance_monitor = ClientAgent.PerformanceMonitor()
        self.performance_monitor.mark_start()

        # send #batch_size many transactions to the edge node
        for hash1_response_batch in self.stub.ExecuteBatch(transaction_batch):
            # print("client received", hash1_response.h1.rw.key.decode(), hash1_response.h1.logIndex)
            start = time.perf_counter()
            for hash1_response in hash1_response_batch.content:
                # self._verify_response(hash1_response)
                self.performance_monitor.mark_phase1_complete()

                hash1 = hash1_response.h1
                if hash1.merkleRoot not in collected_hash1:
                    collected_hash1.add(hash1.merkleRoot)
                    hash1_list.append(hash1)

                merkle_proof = pickle.loads(hash1.merkleProof)  # deserialize
                data = (hash1_response.h1.rw.key, hash1_response.h1.rw.val)  # data to be verified

                assert merklelib.verify_leaf_inclusion(data, merkle_proof, hash_func, hash1.merkleRoot)
            # print("response batch processed using:", time.perf_counter() - start)

        all_hash2_threads = []
        for hash1 in hash1_list:
            thread = threading.Thread(target=self._check_hash2, args=(hash1,))
            all_hash2_threads.append(thread)
            thread.start()

        for thread in all_hash2_threads:
            thread.join()
            self.performance_monitor.mark_phase2_complete()

        self.performance_monitor.print_batch_performance()

    class PerformanceMonitor:
        def __init__(self):
            self.precision = 4
            self.phase1_latency = []
            self.phase2_latency = []
            self.start = None

        def mark_start(self):
            self.start = time.perf_counter()

        def mark_phase1_complete(self):
            latency = time.perf_counter() - self.start
            self.phase1_latency.append(latency)

        def mark_phase2_complete(self):
            latency = time.perf_counter() - self.start
            self.phase2_latency.append(round(latency, self.precision))
            # print("Phase2 ", time.perf_counter() - self.start)

        def print_batch_performance(self):
            print('{} & {} & {}'.format(
                round(mean(self.phase1_latency), self.precision),  # average phase1 latency over all transactions
                round(self.phase1_latency[0], self.precision), # the minimum phase1 latnecy
                self.phase2_latency # a list of phase2 latencies, one for each unique hash1
            ))