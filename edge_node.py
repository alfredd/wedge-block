import wedgeblock_pb2

from merklelib import MerkleTree
import merklelib
import hashlib
import pickle
import threading
import time
from ropsten_connector import *

class LogEntry:
    def __init__(self, index, merkle_tree:MerkleTree):
        self.index = index
        self.merkle_tree = merkle_tree
        self.eth_hash2 = None

    def __str__(self):
        if self.eth_hash2 is None:
            return str(self.index) + " " + str(self.merkle_tree)
        else:
            return str(self.index) + " " + str(self.merkle_tree) + " " + str(self.eth_hash2)

    def set_hash2(self, hash2):
        if self.eth_hash2 is None:
            self.eth_hash2 = hash2

    def has_hash2(self):
        return self.eth_hash2 is not None

    def get_hash2(self):
        if self.has_hash2():
            return self.eth_hash2
        return None


class Log:
    def __init__(self):
        self.l = []

    def get_log_entry(self, index):
        if index < self.get_next_log_index() and index >= 0:
            return self.l[index]
        return None

    def insert(self, logentry:LogEntry):
        self.l.append(logentry)

    def get_next_log_index(self):
        return len(self.l)

    def __str__(self):
        rtn = ""
        for l in self.l:
            rtn += str(l) + "\n"
        return rtn


class EdgeNode():
    def __init__(self):
        self.log = Log()
        self.buffer = []
        self.buffer_check_interval = 10 # seconds
        self.eth_connector = RopEth()
        buffer_check_thread = threading.Thread(target=self.scheduled_buffer_check, name="buffer_check_thread", daemon=True)
        buffer_check_thread.start()
        self.log_added_event = threading.Event()
        self.analyser = EdgeNodeAnalyser()

    def scheduled_buffer_check(self):
        while True:
            time.sleep(self.buffer_check_interval)
            if len(self.buffer) > 0:
                self.process_batch()

    def wait_for_eth(self, txn_hash, data_to_eth):
        while True:
            eth_response = self.eth_connector.getTransactionReciept(txn_hash)
            if eth_response is not None:
                log_index = data_to_eth[1]
                log_entry = self.log.get_log_entry(log_index)
                if log_entry:
                    assert txn_hash == eth_response['transactionHash']
                    log_entry.set_hash2(eth_response['transactionHash']) # third measurement
                    self.analyser.history[log_index].hash2_receive_timestamp = time.perf_counter()
                    print("log entry phase2 complete: \n", log_entry)
                    print("Time analysis: ", self.analyser.history[log_index].get_latency_analysis())
                break

    def process_batch(self):
        time_record = EdgeNodeAnalyser.LogEntryTimeRecord()
        time_record.batch_size = len(self.buffer)

        time_record.batch_process_timestamp = time.perf_counter()  # first measurement
        tree = MerkleTree(self.buffer, self.hash_func)

        next_open_index = self.log.get_next_log_index()
        self.log.insert(LogEntry(next_open_index, tree))
        time_record.log_insertion_timestamp = time.perf_counter()   # second measurement

        self.analyser.add_new_time_record(next_open_index, time_record)

        data_to_eth = (tree.merkle_root, next_open_index)
        txn_hash = self.eth_connector.updateContractData(str(data_to_eth))
        threading.Thread(target=self.wait_for_eth, args=(txn_hash, data_to_eth), daemon=True).start()

        self.log_added_event.set()
        self.buffer.clear()
        print("current log is: \n", self.log)
        self.log_added_event.clear()

    def get_txn_from_client(self, txn: wedgeblock_pb2.Transaction) -> wedgeblock_pb2.Hash1:
        data = (txn.rw.key, txn.rw.val)
        self.buffer.append(data)
        target_index = self.log.get_next_log_index()

        if len(self.buffer) >= 4:
            self.process_batch()
        else:
            self.log_added_event.wait()

        # log entry is added to the log

        log_index = self.log.get_log_entry(target_index).index
        assert log_index == target_index
        tree = self.log.get_log_entry(target_index).merkle_tree
        root = tree.merkle_root
        proof = tree.get_proof(data)
        assert merklelib.verify_leaf_inclusion(data, proof, self.hash_func, root)
        proof_pickle = pickle.dumps(proof)

        hash1 = wedgeblock_pb2.Hash1(rw=txn.rw, merkleRoot=root, merkleProof=proof_pickle)
        hash1.logIndex = target_index
        return hash1

    def reply_h2_to_client(self, request: wedgeblock_pb2.LogHash):
        request_index = request.logIndex
        if self.log.get_log_entry(request_index).has_hash2():
            return self.log.get_log_entry(request_index).get_hash2()
        return None

    def is_valid_index(self, request_index):
        return self.log.get_log_entry(request_index) is not None

    @staticmethod
    def hash_func(value):
        return hashlib.sha256(value).hexdigest()


class EdgeNodeAnalyser:
    def __init__(self):
        self.history = dict()

    def add_new_time_record(self, log_index:int, record):
        self.history[log_index] = record

    class LogEntryTimeRecord:
        def __init__(self):
            self.batch_process_timestamp = None
            self.log_insertion_timestamp = None
            self.hash2_receive_timestamp = None
            self.batch_size = 0

        def get_latency_analysis(self):
            return "{}, {}, {}, {}".format(self.batch_size,
                                           self.log_insertion_timestamp - self.batch_process_timestamp,
                                           self.hash2_receive_timestamp - self.log_insertion_timestamp,
                                           self.hash2_receive_timestamp - self.batch_process_timestamp
            )

        def __str__(self):
            return "{}, {}, {}".format(self.batch_process_timestamp,
                                       self.log_insertion_timestamp,
                                       self.hash2_receive_timestamp)

