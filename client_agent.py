from Crypto.Hash import SHA256

import time
import multiprocessing as mp
import threading

from block_validator import BlockValidator

import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb

from credential_tools import signer, verify_hash1_response


def make_transaction(key, val, seq) -> wb.Transaction:
    if type(key) is str and type(val) is str:
        key = str.encode(key)
        val = str.encode(val)
    txn_content_hash = SHA256.new(key + val + str(seq).encode())
    txn_signature = signer.sign(txn_content_hash)
    return wb.Transaction(key=key, val=val, sequenceNumber=seq, signature=txn_signature)


class ClientAgent:
    def __init__(self, client_id: int):
        self.stub = None
        self.bc_block_validator = BlockValidator()
        self.id = client_id
        self.hash2_checking_interval = 3
        self.batch_size = 10000
        self.txn_key_size = 64
        self.txn_val_size = 1024

    def _check_hash2(self, hash1: wb.Hash1):
        log_hash = wb.LogHash(logIndex=hash1.logIndex, merkleRoot=hash1.merkleRoot)
        hash2 = self.stub.GetPhase2Hash(log_hash)
        if hash2.status is wb.Hash2Status.INVALID:
            # raise Exception
            raise Exception("logHash ", log_hash, " is invalid")

        while hash2.status is not wb.Hash2Status.VALID:
            hash2 = self.stub.GetPhase2Hash(log_hash)
            time.sleep(self.hash2_checking_interval)
        self.bc_block_validator.thread_safe_verify(hash1.merkleRoot, hash1.logIndex)
        # self.bc_block_validator.thread_safe_verify(hash2.TxnHash, hash1.merkleRoot, hash1.logIndex)

    def run(self, stub: wbgrpc.EdgeNodeStub):
        # pool = mp.get_context('spawn').Pool(mp.cpu_count())
        pool = mp.Pool(mp.cpu_count())

        self.stub = stub
        start_t = time.perf_counter()

        batch_size = self.batch_size
        client_first_key = self.id * batch_size

        result_objects = []
        for i in range(client_first_key, client_first_key+batch_size):
            result_objects.append(pool.apply_async(make_transaction,
                                                   args=(i.to_bytes(self.txn_key_size, 'big'),
                                                         i.to_bytes(self.txn_val_size, 'big'), i)))
        workload = [r.get() for r in result_objects]
        transaction_batch = wb.TransactionBatch(content=workload)

        request_generated_t = time.perf_counter()
        print("workload generated using: ", round(request_generated_t - start_t, 4))

        received_unique_hash1 = dict()
        result_objects = []
        # send #batch_size many transactions to the edge node
        request_sent_t = time.perf_counter()
        first_response_received_t = None
        sequence_number = 0
        for hash1_response in self.stub.ExecuteBatch(transaction_batch):
            if first_response_received_t is None:
                first_response_received_t = time.perf_counter()
            result_objects.append(pool.apply_async(verify_hash1_response,
                                                   args=(hash1_response, workload[sequence_number])))
            # extract unique hash1s for hash2 queries
            # several hash1s might have been placed in the same bc txn thus sharing same hash2
            if hash1_response.h1.logIndex not in received_unique_hash1:
                received_unique_hash1[hash1_response.h1.logIndex] = hash1_response.h1
            sequence_number += 1
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

        print("Avg time (per txn) on signature verification: ", round(total_sig_verify_t / batch_size, 4))
        print("Avg time (per txn) on merkle proof verification: ", round(total_tree_inclusion_verify_t / batch_size, 4))

        print("Total phase1 latency (all sent out -> all verified): ", round(end_t - request_sent_t, 4))
        print("Phase1 Throughput: ", round(batch_size/(end_t - request_sent_t), 4))

        # for each unique hash1, ask server for its hash2
        hash2_verify_start = time.perf_counter()
        all_hash2_threads = []
        for k, hash1 in received_unique_hash1.items():
            thread = threading.Thread(target=self._check_hash2, args=(hash1,))
            all_hash2_threads.append(thread)
            thread.start()

        for thread in all_hash2_threads:
            thread.join()
        hash2_verify_end = time.perf_counter()
        print("Total phase2 latency (all hash2 verified): ", round(hash2_verify_end - hash2_verify_start, 4))
        return
