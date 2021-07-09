from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

import threading
import pickle
import merklelib
import hashlib
import time

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
            print("The response is authentic.")
        except ValueError:
            print("The response is not authentic.")

    def _check_hash2(self, hash1: wb.Hash1):
        logHash = wb.LogHash(logIndex=hash1.logIndex, merkleRoot=hash1.merkleRoot.encode())
        hash2 = self.stub.GetPhase2Hash(logHash)
        if hash2.status is wb.Hash2Status.INVALID:
            # raise Exception
            print("logHash ", logHash, " is invalid")

        while hash2.status is not wb.Hash2Status.VALID:
            hash2 = self.stub.GetPhase2Hash(logHash)
            time.sleep(self.hash2_checking_interval)
        cb = CallBackValidator()
        self.bc_block_validator.insert_to_verify(hash2.TxnHash, hash1.merkleRoot, hash1.logIndex, cb.call_back)

    def _send_request(self, key: str, val: str):
        txn_content = wb.RWSet(type=wb.TxnType.RW, key=key, val=val)
        txn_signature = self._sign_request(txn_content)
        t = wb.Transaction(rw=txn_content, signature=txn_signature)

        self.performance_monitor.mark_start()

        hash1_response = self.stub.Execute(t)
        self._verify_response(hash1_response)

        self.performance_monitor.mark_phase1_complete()

        hash1 = hash1_response.h1
        merkle_proof = pickle.loads(hash1.merkleProof)  # deserialize
        data = (t.rw.key, t.rw.val)  # data to be verified

        assert merklelib.verify_leaf_inclusion(data, merkle_proof, hash_func, hash1.merkleRoot)

        self._check_hash2(hash1)
        self.performance_monitor.mark_phase2_complete()

    def run(self, stub: wbgrpc.EdgeNodeStub, max_threads: int):
        self.stub = stub
        all_threads = []
        self.performance_monitor = ClientAgent.PerformanceMonitor(max_threads)

        for i in range(max_threads):
            thread = threading.Thread(target=self._send_request, args=(str(i), str(i * i)))
            all_threads.append(thread)
            thread.start()

        for thread in all_threads:
            thread.join()

        self.performance_monitor.print_performance()

    class PerformanceMonitor:
        def __init__(self, agent_count:int):
            self.precision = 4
            self.phase1_latency = 0
            self.phase2_latency = 0
            self.latency_update_lock = threading.Lock()
            self.agent_count = agent_count
            self.start = None

        def mark_start(self):
            self.start = time.perf_counter()

        def mark_phase1_complete(self):
            t = time.perf_counter()
            self.latency_update_lock.acquire()
            self.phase1_latency += t - self.start
            print("Phase1, ", (t - self.start))
            self.latency_update_lock.release()

        def mark_phase2_complete(self):
            self.latency_update_lock.acquire()
            self.phase2_latency += time.perf_counter() - self.start
            print("Phase2 ", time.perf_counter() - self.start)
            self.latency_update_lock.release()

        def print_performance(self):
            # average over all requests
            print('{} & {}'.format(round(self.phase1_latency / self.agent_count, self.precision),
                                   round(self.phase2_latency / self.agent_count, self.precision)))