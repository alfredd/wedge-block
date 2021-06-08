import wedgeblock_pb2

from merklelib import MerkleTree
import merklelib
import hashlib
import pickle
import codecs
import threading
import time
from ropsten_connector import *


class EdgeNode:
    def __init__(self):
        self.log = Log()
        self.buffer = []
        self.buffer_check_interval = 10  # seconds
        self.max_buffer_size = 10
        self.buffer_lock = threading.Lock()

        self.eth_connector = RopEth()
        self.analyser = EdgeNodeAnalyser()

        # threading.Thread(target=self.scheduled_buffer_check, name="buffer_check_thread", daemon=True).start()
        self.log_added_event = threading.Event()

        self.hash2_waiting_list = dict()
        self.hash2_manager_lock = threading.Lock()
        self.hash2_manager_thread = threading.Thread(target=self.hash2_manager, name="hash2_manager_thread",
                                                     daemon=True)

    def scheduled_buffer_check(self):
        while True:
            time.sleep(self.buffer_check_interval)
            if len(self.buffer) > 0:
                self.process_batch()

    def hash2_manager(self):
        print("hash2 manager invoked \n")
        while len(self.hash2_waiting_list) != 0:
            print("hash2 manager updating contract \n")
            self.hash2_manager_lock.acquire()
            waiting_indexes = list(self.hash2_waiting_list.keys())
            data_to_eth = codecs.encode(pickle.dumps(self.hash2_waiting_list), "base64").decode()
            txn_hash = self.eth_connector.updateContractData(data_to_eth)
            self.hash2_waiting_list.clear()
            self.hash2_manager_lock.release()
            # waiting for eth to write into a block
            while True:
                time.sleep(5)
                eth_response = self.eth_connector.getTransactionReciept(txn_hash)
                if eth_response is not None:
                    assert txn_hash == eth_response['transactionHash']
                    # print(waiting_indexes)
                    for index in waiting_indexes:
                        log_entry = self.log.get_log_entry(index)
                        if log_entry:
                            log_entry.set_hash2(eth_response['transactionHash'])  # third measurement
                            self.analyser.history[index].hash2_receive_ts = time.perf_counter()
                            print("log entry phase2 complete: \n", log_entry)
                            print("Time analysis: ", self.analyser.history[index].get_latency_analysis())
                    break
        print("hash2 manager exit \n")

    def process_batch(self):
        self.buffer_lock.acquire()
        if len(self.buffer) == 0:
            self.buffer_lock.release()
            return
        time_record = EdgeNodeAnalyser.LogEntryTimeRecord()
        time_record.batch_size = len(self.buffer)

        time_record.batch_process_ts = time.perf_counter()  # first measurement
        tree = MerkleTree(self.buffer, self.hash_func)

        next_open_index = self.log.get_next_log_index()
        self.log.insert(LogEntry(next_open_index, tree))
        time_record.log_insertion_ts = time.perf_counter()  # second measurement

        self.analyser.add_new_time_record(next_open_index, time_record)

        self.hash2_manager_lock.acquire()
        self.hash2_waiting_list[next_open_index] = tree.merkle_root
        self.hash2_manager_lock.release()
        if not self.hash2_manager_thread.is_alive():
            self.hash2_manager_thread = threading.Thread(target=self.hash2_manager, name="hash2_manager_thread",
                                                         daemon=True)
            self.hash2_manager_thread.start()

        # data_to_eth = (tree.merkle_root, next_open_index)
        # txn_hash = self.eth_connector.updateContractData(str(data_to_eth))
        # threading.Thread(target=self.wait_for_eth, args=(txn_hash, data_to_eth), daemon=True).start()

        self.log_added_event.set()
        self.buffer.clear()
        print("current log is: \n", self.log)
        self.log_added_event.clear()
        self.buffer_lock.release()

    def get_txn_from_client(self, txn: wedgeblock_pb2.Transaction) -> wedgeblock_pb2.Hash1:
        data = (txn.rw.key, txn.rw.val)
        self.buffer_lock.acquire()
        self.buffer.append(data)
        self.buffer_lock.release()
        target_index = self.log.get_next_log_index()

        if len(self.buffer) >= self.max_buffer_size:
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


class LogEntry:
    def __init__(self, index, merkle_tree: MerkleTree):
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
        self.entries = []

    def get_log_entry(self, index):
        if 0 <= index < self.get_next_log_index():
            return self.entries[index]
        return None

    def insert(self, log_entry: LogEntry):
        self.entries.append(log_entry)

    def get_next_log_index(self):
        return len(self.entries)

    def __str__(self):
        rtn = ""
        for entry in self.entries:
            rtn += str(entry) + "\n"
        return rtn


class EdgeNodeAnalyser:
    def __init__(self):
        self.history = dict()

    def add_new_time_record(self, log_index: int, record):
        self.history[log_index] = record

    class LogEntryTimeRecord:
        precision = 4

        def __init__(self):
            self.batch_process_ts = None
            self.log_insertion_ts = None
            self.hash2_receive_ts = None
            self.batch_size = 0

        def get_latency_analysis(self):
            return "{} & {} & {} & {}".format(self.batch_size,
                                              round(self.log_insertion_ts - self.batch_process_ts, self.precision),
                                              round(self.hash2_receive_ts - self.log_insertion_ts, self.precision),
                                              round(self.hash2_receive_ts - self.batch_process_ts, self.precision)
                                              )

        def __str__(self):
            return "{}, {}, {}".format(self.batch_process_ts,
                                       self.log_insertion_ts,
                                       self.hash2_receive_ts)
