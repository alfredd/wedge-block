import wedgeblock_pb2

from merklelib import MerkleTree
from statistics import mean
import hashlib
import pickle
import codecs
import threading
import time
from ropsten_connector import *

class LogEntry:
    # an entry simulating the structure of a block in blockchain (no prev_hash used yet)
    # provide basic functionalities on manipulating the entry: VIEW and SET
    # Contains: 1) the index of the Log where itself resides
    #           2) A merkle tree of unfixed size, where leaf node is a (key,val) tuple
    #           3) A public blockchain transaction hash where the merkle tree root info is writen on chain
    def __init__(self, index, merkle_tree: MerkleTree):
        # fixed immutable index and merkle tree info at initialization time
        self.index = index
        self.merkle_tree = merkle_tree
        self.eth_hash2 = None

    def set_hash2(self, hash2):
        # immutable once hash2 is set
        # return True is hash2 is successfully updated, False otherwise
        if self.eth_hash2 is None:
            self.eth_hash2 = hash2
            return True
        return False

    def has_hash2(self):
        return self.eth_hash2 is not None

    def get_hash2(self):
        return self.eth_hash2

    def __str__(self):
        description = "LogEntry at index " + str(self.index) + " with hash1: " + str(self.merkle_tree)
        if self.eth_hash2 is not None:
            description += " and hash2: " + str(self.eth_hash2)
        return description


class Log:
    # a list of LogEntries simulating the structure of a blockchain (no prev_hash used yet)
    # provide basic functionalities on manipulating the log: VIEW and ADD
    def __init__(self):
        self.entries = []
        self.lock = threading.Lock()

    def get_log_entry(self, index):
        if 0 <= index < self.get_next_log_index():
            return self.entries[index]
        return None

    def insert(self, log_entry: LogEntry):
        self.entries.append(log_entry)

    def safe_append(self, log_entry: LogEntry, target_index: int):
        self.lock.acquire()
        if target_index == len(self.entries):
            self.entries.append(log_entry)
            self.lock.release()
            return True
        self.lock.release()
        return False

    def get_next_log_index(self):
        return len(self.entries)

    def get_most_recent_entry(self):
        return self.entries[-1]

    def __str__(self):
        rtn = ""
        for entry in self.entries:
            rtn += str(entry) + "\n"
        return rtn


class EdgeNodeKernel:
    # provide operations on the Log
    def __init__(self):
        # initialize a empty log
        self.log = Log()

    def add_entry(self, data: [(bytes,bytes)], tree=None):
        # Input: list of (key,val) pair, each pair represent one transaction to be added
        #        optional: a merkle tree to skip Action 1
        # Action: 1) generate a merkle tree using the input (if necessary)
        #         2) generate a log entry using the merkle tree
        #         3) add the log entry into the log
        # Output: the index in the log where the newly generated entry resides at

        if tree is None:
            tree = MerkleTree(data, self.hash_func)
        target_index = self.log.get_next_log_index()
        if not self.log.safe_append(LogEntry(target_index, tree), target_index):
            target_index = self.add_entry(data,tree)
        return target_index

    def get_log_entry(self, index: int):
        return self.log.get_log_entry(index)

    def update_hash2(self, index:int, hash2):
        # return True if logEntry at index exits and its hash2 is successfully updated
        # return False otherwise
        entry = self.log.get_log_entry(index)
        if entry is None:
            return False
        return entry.set_hash2(hash2)

    @staticmethod
    def hash_func(value):
        return hashlib.sha256(value).hexdigest()


class EdgeNode:
    def __init__(self):
        self.kernel = EdgeNodeKernel()
        self.eth_connector = RopEth()
        self.analyser = EdgeNodeAnalyser()

        self.hash2_waiting_list = dict()
        self.hash2_manager_lock = threading.Lock()
        self.hash2_manager_thread = threading.Thread(target=self.hash2_manager, name="hash2_manager_thread",
                                                     daemon=True)
        self.total_gas_spent = 0
        self.total_h2_waiting_time = 0

    def hash2_manager(self):
        print("[H2]: hash2 manager invoked \n")
        while len(self.hash2_waiting_list) != 0:
            time.sleep(5)
            print("[H2]: hash2 manager updating contract \n")
            self.hash2_manager_lock.acquire()
            waiting_indexes = list(self.hash2_waiting_list.keys())
            print("[H2]: Writing {} index/merkleRoot pairs to public blockchain".format(len(waiting_indexes)))
            hash2_request_sent = time.perf_counter()
            data_to_eth = json.dumps(self.hash2_waiting_list)
            txn_hash = self.eth_connector.updateContractData(data_to_eth)

            self.hash2_waiting_list.clear()
            self.hash2_manager_lock.release()
            # waiting for eth to write into a block
            while True:
                # check with public blockchain to see if transaction is committed
                eth_response = self.eth_connector.getTransactionReciept(txn_hash)
                if eth_response is not None:
                    assert txn_hash == eth_response['transactionHash']

                    self.total_gas_spent += eth_response['gasUsed']
                    hash2_response_waiting_time = round(time.perf_counter() - hash2_request_sent,4)
                    self.total_h2_waiting_time += hash2_response_waiting_time
                    print("[H2]: Hash2 response for {} log indexes is received after {} seconds."
                          .format(len(waiting_indexes), hash2_response_waiting_time, 4))
                    print("[H2]: Total waiting time  used so far: ", self.total_h2_waiting_time)
                    print("[H2]: Total gas used so far          : ", self.total_gas_spent)

                    for index in waiting_indexes:
                        self.kernel.update_hash2(index, txn_hash)
                        self.analyser.history[index].hash2_received = time.perf_counter()
                        # print(self.analyser.history[index])
                        # print("Phase2 complete: ", self.kernel.get_log_entry(index))
                        # print("Time analysis: ", self.analyser.history[index])
                    break
        print("[H2]: hash2 manager exit \n")

    def process_txn_batch(self, txn_batch: [(wedgeblock_pb2.Transaction)]) -> [wedgeblock_pb2.Hash1]:
        # Input: list of transactions to be added into the log
        # Action: 1) pass input list to the kernel to be added
        #         2) invoke hash2 manager thread to complete the hash2 part of the newly added entry
        #            this thread runs in parallel and can takes much longer time
        #         3) initialize a time record object for the newly added entry
        #            and record timestamps before/after entry creation
        # Output: list of hash1, each correspond to one transaction

        time_record = self.analyser.LogEntryTimeRecord()
        time_record.batch_size = len(txn_batch)
        time_record.process_start = time.perf_counter()  # first measurement

        entry_content = [(txn.rw.key, txn.rw.val) for txn in txn_batch]
        log_index = self.kernel.add_entry(entry_content)
        log_entry = self.kernel.get_log_entry(log_index)

        time_record.entry_added = time.perf_counter()  # second measurement

        self.analyser.add_new_time_record(log_index, time_record)

        self.hash2_manager_lock.acquire()
        self.hash2_waiting_list[log_index] = log_entry.merkle_tree.merkle_root
        self.hash2_manager_lock.release()
        if not self.hash2_manager_thread.is_alive():
            self.hash2_manager_thread = threading.Thread(target=self.hash2_manager, name="hash2_manager_thread",
                                                         daemon=True)
            self.hash2_manager_thread.start()

        # log entry is added to the log
        tree = log_entry.merkle_tree
        root = tree.merkle_root
        hash1_list = []
        for txn in txn_batch:
            txn_id = (txn.rw.key, txn.rw.val)
            proof = tree.get_proof(txn_id)
            proof_pickle = pickle.dumps(proof)
            hash1 = wedgeblock_pb2.Hash1(logIndex=log_index, rw=txn.rw, merkleRoot=root, merkleProof=proof_pickle)
            hash1_list.append(hash1)
        self.analyser.history[log_index].hash1_responses_ready = time.perf_counter() # third measurement

        # print(self.analyser.history[log_index].get_hash1_latency_analysis())
        return hash1_list

    def get_h2_at_index(self, index):
        return self.kernel.get_log_entry(index).get_hash2()

    def entry_exist_at_index(self, index):
        return self.kernel.get_log_entry(index) is not None


class EdgeNodeAnalyser:
    def __init__(self):
        self.history = dict()

    def add_new_time_record(self, log_index: int, record):
        self.history[log_index] = record

    def get_avg_record(self):
        avg_tree_gen = 0
        avg_h1_prep = 0
        for entry_record in self.history.values():
            avg_tree_gen += entry_record.entry_added - entry_record.process_start
            avg_h1_prep += entry_record.hash1_responses_ready - entry_record.entry_added
        return "Avg time per batch (tree_gen): {}\n" \
               "Avg time per batch (h1_prep): {}".format(
            round(avg_tree_gen/len(self.history),4),
            round(avg_h1_prep/len(self.history),4))


    class LogEntryTimeRecord:
        def __init__(self):
            self.precision = 4
            self.batch_size = 0
            self.process_start = 0
            self.entry_added = 0
            self.hash1_responses_ready = 0
            self.hash2_received = 0

        def get_hash1_latency_analysis(self):
            return "Batch of {} transactions completed: \n" \
                   "Tree construction: {} \n" \
                   "Hash1 response preparation: {} \n" \
                   "Total: {}".format(
                self.batch_size,
                round(self.entry_added - self.process_start, self.precision),
                round(self.hash1_responses_ready - self.entry_added, self.precision),
                round(self.hash1_responses_ready - self.process_start, self.precision)
            )

        def get_latency_analysis(self):
            return "Batch of {} transactions completed: \n" \
                   "Tree construction: {} \n" \
                   "Hash1 response preparation: {} \n" \
                   "Hash2 response preparation: {} \n" \
                   "Total: {}".format(
                self.batch_size,
                round(self.entry_added - self.process_start, self.precision),
                round(self.hash1_responses_ready - self.entry_added, self.precision),
                round(self.hash2_received - self.entry_added, self.precision),
                round(self.hash2_received - self.process_start, self.precision)
            )

        def __str__(self):
            return "{} & {} & {} & {} & {}".format(
                self.batch_size,
                round(self.entry_added - self.process_start, self.precision),
                round(self.hash1_responses_ready - self.entry_added, self.precision),
                round(self.hash2_received - self.entry_added, self.precision),
                round(self.hash2_received - self.process_start, self.precision)
            )
