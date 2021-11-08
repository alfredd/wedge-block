from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

import pickle
import merklelib
import hashlib
import time
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
        txn_content_hash = SHA256.new(request_content.SerializeToString())
        txn_signature = self.signer.sign(txn_content_hash)
        return txn_signature

    def _verify_response(self, hash1_response: wb.Hash1Response):
        hash1 = hash1_response.h1
        response_signature = hash1_response.signature
        received_response_hash = SHA256.new(hash1.SerializeToString())
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
        txn_signature = self._sign_request(txn_content)
        # txn_signature = None
        return wb.Transaction(rw=txn_content, signature=txn_signature)

    def _generate_transaction_batch(self, total_number) -> wb.TransactionBatch:
        transaction_batch = wb.TransactionBatch()
        for i in range(total_number):
            t = self._make_transaction(i.to_bytes(8,'big'), i.to_bytes(64,'big'))
            transaction_batch.content.append(t)
        return transaction_batch

    def run(self, stub: wbgrpc.EdgeNodeStub):
        self.stub = stub
        start = time.perf_counter()

        batch_size = 10000
        transaction_batch = self._generate_transaction_batch(batch_size)
        print("workload generated using: ", round(time.perf_counter() - start, 4))

        unique_hash1 = dict()

        self.performance_monitor = ClientAgent.PerformanceMonitor()
        self.performance_monitor.mark_start()

        total_sig_verify = 0
        total_tree_inclusion_verify = 0

        # send #batch_size many transactions to the edge node
        for hash1_response in self.stub.ExecuteBatch(transaction_batch):
            ##### for hash1_response in hash1_response_batch.content:
            # verify the signature is correct
            sig_verify_start = time.perf_counter()
            self._verify_response(hash1_response)
            total_sig_verify += time.perf_counter() - sig_verify_start

            # identify unique hash1 root to prepare for hash2 queries
            hash1 = hash1_response.h1
            if hash1.merkleRoot not in unique_hash1:
                unique_hash1[hash1.merkleRoot] = hash1

            # verify the merkle proof is correct
            tree_inclusion_verify_start = time.perf_counter()
            merkle_proof = pickle.loads(hash1.merkleProof)  # deserialize
            data = (hash1_response.h1.rw.key, hash1_response.h1.rw.val)  # data to be verified
            assert merklelib.verify_leaf_inclusion(data, merkle_proof, hash_func, hash1.merkleRoot)
            total_tree_inclusion_verify += time.perf_counter() - tree_inclusion_verify_start

            self.performance_monitor.mark_phase1_complete()
        self.performance_monitor.mark_done()

        # all_hash2_threads = []
        # for hash1 in unique_hash1.values():
        #     thread = threading.Thread(target=self._check_hash2, args=(hash1,))
        #     all_hash2_threads.append(thread)
        #     thread.start()
        #
        # for thread in all_hash2_threads:
        #     thread.join()
        #     self.performance_monitor.mark_phase2_complete()

        print("Total time on signature verification: ", round(total_sig_verify,4))
        print("Average time on signature verification: ", round(total_sig_verify/batch_size,4))
        print("Total time on merkle proof verification: ", round(total_tree_inclusion_verify,4))
        print("Average time on merkle proof verification:", round(total_tree_inclusion_verify/batch_size,4))
        self.performance_monitor.print_workload_performance()

    class PerformanceMonitor:
        def __init__(self):
            self.precision = 4
            self.phase1_latency = []
            self.phase2_latency = []
            self.start = None
            self.done = None

        def mark_start(self):
            self.start = time.perf_counter()

        def mark_done(self):
            self.done = time.perf_counter()

        def mark_phase1_complete(self):
            latency = time.perf_counter() - self.start
            self.phase1_latency.append(latency)

        def mark_phase2_complete(self):
            latency = time.perf_counter() - self.start
            self.phase2_latency.append(round(latency, self.precision))
            # print("Phase2 ", time.perf_counter() - self.start)

        def print_workload_performance(self):
            print('Average phase1 latency: {} \n'
                  'Total phase1 latency:   {} \n'
                  'Minimum phase1 latency: {} \n'
                  'Phase1 Throughput:      {} \n'
                  'Phase2 latency:         {}'.format(
                round(mean(self.phase1_latency), self.precision),  # average phase1 latency over all transactions
                round(self.done - self.start, self.precision), # total phase1 latency
                round(self.phase1_latency[0], self.precision), # the minimum phase1 latency
                round(len(self.phase1_latency)/ (self.done - self.start), self.precision), # throughput
                self.phase2_latency # a list of phase2 latencies, one for each unique hash1
            ))

        def get_workload_performance(self):
            return "{} & {} & {} & {}".format(
                round(mean(self.phase1_latency), self.precision),  # average phase1 latency over all transactions
                round(self.phase1_latency[0], self.precision), # the minimum phase1 latency
                round(len(self.phase1_latency)/ (self.done - self.start), self.precision), # throughput
                self.phase2_latency # a list of phase2 latencies, one for each unique hash1
            )