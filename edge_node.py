import wedgeblock_pb2 as wb

from merklelib import MerkleTree
import hashlib
import pickle
import threading
import time
from collections import defaultdict
from hash1_store_contract import *


class LogEntry:
    # an entry simulating the structure of a block in blockchain (no prev_hash used yet)
    # provide basic functionalities on manipulating the entry: VIEW and SET
    # Contains: 1) the index of the Log where itself resides
    #           2) A merkle tree of unfixed size, where leaf node is a (key,val) tuple
    #           3) A public blockchain transaction hash where the merkle tree root info is writen on chain
    def __init__(self, index, merkle_tree: MerkleTree):
        # fixed immutable index and merkle tree info at initialization time
        self._index = index
        self._merkle_tree = merkle_tree
        self._eth_hash2 = None

    def set_hash2(self, hash2):
        # immutable once hash2 is set
        # return True is hash2 is successfully updated, False otherwise
        if self._eth_hash2 is None:
            self._eth_hash2 = hash2
            return True
        return False

    @property
    def merkle_tree(self):
        return self._merkle_tree

    def has_hash2(self):
        return self._eth_hash2 is not None

    def get_hash2(self):
        return self._eth_hash2

    def __str__(self):
        description = "LogEntry at index " + str(self._index) + " with hash1: " + str(self._merkle_tree)
        if self._eth_hash2 is not None:
            description += " and hash2: " + str(self._eth_hash2)
        return description


class Log:
    # a list of LogEntries simulating the structure of a blockchain (no prev_hash used yet)
    # provide basic functionalities on manipulating the log: VIEW and ADD
    def __init__(self):
        self._entries = []
        self._lock = threading.Lock()

    def get_log_entry(self, index):
        if 0 <= index < self.get_next_log_index():
            return self._entries[index]
        return None

    def insert(self, log_entry: LogEntry):
        self._entries.append(log_entry)

    def safe_append(self, log_entry: LogEntry, target_index: int):
        self._lock.acquire()
        if target_index == len(self._entries):
            self._entries.append(log_entry)
            self._lock.release()
            return True
        self._lock.release()
        return False

    def get_next_log_index(self):
        return len(self._entries)

    def get_most_recent_entry(self):
        return self._entries[-1]

    def __str__(self):
        rtn = ""
        for entry in self._entries:
            rtn += str(entry) + "\n"
        return rtn


class EdgeNodeKernel:
    # provide operations on the Log
    def __init__(self):
        # initialize a empty log
        self._log = Log()

    def add_entry(self, data: [(bytes, bytes)], tree=None):
        # Input: list of (key,val) pair, each pair represent one transaction to be added
        #        optional: a merkle tree to skip Action 1
        # Action: 1) generate a merkle tree using the input (if necessary)
        #         2) generate a log entry using the merkle tree
        #         3) add the log entry into the log
        # Output: the index in the log where the newly generated entry resides at

        if tree is None:
            tree = MerkleTree(data, self.hash_func)
        target_index = self._log.get_next_log_index()
        if not self._log.safe_append(LogEntry(target_index, tree), target_index):
            target_index = self.add_entry(data, tree)
        return target_index

    def get_log_entry(self, index: int):
        return self._log.get_log_entry(index)

    def update_hash2(self, index: int, hash2):
        # return True if logEntry at index exits and its hash2 is successfully updated
        # return False otherwise
        entry = self._log.get_log_entry(index)
        if entry is None:
            return False
        return entry.set_hash2(hash2)

    @staticmethod
    def hash_func(value):
        return hashlib.sha256(value).hexdigest()


class EdgeNodeStorage:
    def __init__(self):
        """
        self._storage structure
        key: log index
        value: dictionary of {
            key: txn key
            value: (txn val, txn seq)
        }

        self._key_lookup_table structure
        key: txn key
        value: log index
        """
        self._storage = dict()
        self._key_lookup_table = dict()

    def add(self, log_index: int, key, content):
        if log_index not in self._storage:
            self._storage[log_index] = dict()
        self._storage[log_index][key] = content
        self._key_lookup_table[key] = log_index

    def key_location_lookup(self, key):
        # return None if not exist
        return self._key_lookup_table.get(key)

    def get_txn(self, key):
        log_index = self.key_location_lookup(key)
        if log_index is not None:
            # txn must exist
            val, seq = self._storage[log_index][key]
            return log_index, key, val, seq
        else:
            # txn does not exist
            return None, key, None,None

    def get_all_txn_at(self, log_index):
        txn_list = []
        for key, (val, seq) in self._storage[log_index].items():
            txn_list.append((key, val, seq))
        return txn_list


class EdgeNode:
    def __init__(self):
        self.kernel = EdgeNodeKernel()
        self.storage = EdgeNodeStorage()
        self.eth_connector = Hash1StoreContract()
        self.analyser = EdgeNodeAnalyser()

        self.hash2_waiting_buffer = dict()
        self._hash2_manager_lock = threading.Lock()
        self._hash2_manager_thread = threading.Thread(
            target=self._hash2_manager, name="_hash2_manager_thread", daemon=True)
        self.total_gas_spent = 0
        self.total_h2_waiting_time = 0

    def _hash2_manager(self):
        # Ropsten Eth transaction cannot be processed if its size is too large (max gas allowance exceeded)
        # therefore we set a upper bound to how many hash1 proofs are sent on-chain in one transaction
        buffer_threshold = 200
        print("[H2]: hash2 manager invoked \n")
        while len(self.hash2_waiting_buffer) != 0:
            time.sleep(5)
            print("[H2]: hash2 manager updating contract \n")
            self._hash2_manager_lock.acquire()
            # a temp buffer is used to hold extra hash1 proofs
            temp_buffer = None
            if len(self.hash2_waiting_buffer) > buffer_threshold:
                temp = list(self.hash2_waiting_buffer.items())
                self.hash2_waiting_buffer = dict(temp[:buffer_threshold])
                temp_buffer = dict(temp[buffer_threshold:])

            waiting_indexes = list(self.hash2_waiting_buffer.keys())
            print("[H2]: Writing {} index/merkleRoot pairs to public blockchain".format(len(waiting_indexes)))
            hash2_request_sent = time.perf_counter()
            merkle_roots = list(self.hash2_waiting_buffer.values())
            txn_hash = self.eth_connector.update(merkle_roots, waiting_indexes[0])

            self.hash2_waiting_buffer.clear()
            if temp_buffer is not None:
                self.hash2_waiting_buffer = temp_buffer
            self._hash2_manager_lock.release()
            # waiting for eth to write into a block
            while True:
                # check with public blockchain to see if transaction is committed
                eth_response = self.eth_connector.getTransactionReceipt(txn_hash)
                if eth_response is not None:
                    assert txn_hash == eth_response['transactionHash']

                    self.total_gas_spent += eth_response['gasUsed']
                    hash2_response_waiting_time = round(time.perf_counter() - hash2_request_sent, 4)
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

    def _generate_hash1_list(self, log_index, raw_leaves_data):
        # Input:  1) log index
        #         2) a list of raw leaves data (key, val, seq) or None
        # Action: 1) generate merkle proof for every raw leaf data
        # Output: list of hash1, each correspond to one raw leaf data

        log_entry = self.kernel.get_log_entry(log_index)
        tree = log_entry.merkle_tree
        hash1_list = []
        for key, val, seq in raw_leaves_data:
            if val is None and seq is None:
                hash1_list.append(wb.Hash1(logIndex=log_index,
                                           rw=wb.RWSet(type=wb.TxnType.RO, key=key, val=None),
                                           merkleRoot=None,
                                           merkleProof=None, sequenceNumber=None))
                continue
            rw_set = wb.RWSet(type=wb.TxnType.RW, key=key, val=val)
            proof = tree.get_proof((key, val, seq))
            proof_pickle = pickle.dumps(proof)
            hash1 = wb.Hash1(logIndex=log_index,
                             rw=rw_set,
                             merkleRoot=tree.merkle_root,
                             merkleProof=proof_pickle,
                             sequenceNumber=seq)
            hash1_list.append(hash1)
        return hash1_list

    def process_txn_batch(self, txn_batch: [wb.Transaction]) -> [wb.Hash1]:
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

        entry_content = [(txn.rw.key, txn.rw.val, txn.sequenceNumber) for txn in txn_batch]
        log_index = self.kernel.add_entry(entry_content)
        log_entry = self.kernel.get_log_entry(log_index)

        time_record.entry_added = time.perf_counter()  # second measurement

        self.analyser.add_new_time_record(log_index, time_record)

        # inform(invoke) hash2 manager about the new merkle_root
        self._hash2_manager_lock.acquire()
        self.hash2_waiting_buffer[log_index] = log_entry.merkle_tree.merkle_root
        self._hash2_manager_lock.release()
        if not self._hash2_manager_thread.is_alive():
            self._hash2_manager_thread = threading.Thread(
                target=self._hash2_manager, name="_hash2_manager_thread", daemon=True)
            self._hash2_manager_thread.start()

        raw_leaves_data = []
        for txn in txn_batch:
            raw_leaves_data.append((txn.rw.key, txn.rw.val, txn.sequenceNumber))
            self.storage.add(log_index, txn.rw.key, (txn.rw.val, txn.sequenceNumber))
        hash1_list = self._generate_hash1_list(log_index, raw_leaves_data)

        self.analyser.history[log_index].hash1_responses_ready = time.perf_counter()  # third measurement

        return hash1_list

    def get_h2_at_index(self, log_index):
        return self.kernel.get_log_entry(log_index).get_hash2()

    def entry_exist_at_index(self, log_index):
        return self.kernel.get_log_entry(log_index) is not None

    def answer_query(self, keys):
        # Input:  1) a list of keys (txns stored at the edge came in as (key, value, seq)
        # Action: 1) extract all txns out of storage
        #         2) generate hash1 for each txns using the merkle tree stored at input index
        # Output: dict of hash1, key: txn_key, val: corresponding hash1 (None is key does not exit)

        # aggregate extracted txns base on log indexes
        txn_in_storage = defaultdict(list)
        for key in keys:
            log_index, key, val, seq = self.storage.get_txn(key)
            txn_in_storage[log_index].append((key, val, seq))

        hash1_list = []
        for log_index, raw_txn_list in txn_in_storage.items():
            hash1_list.extend(self._generate_hash1_list(log_index, raw_txn_list))
        return hash1_list

    def answer_full_log_query(self, log_indexes):
        # Input:  1) a list of log index
        # Action: 1) extract all txns in all log positions out of storage
        #         2) generate hash1 for each txns using the merkle tree stored at input index
        # Output: list of hash1, each correspond to one transaction
        hash1_list = []
        for log_index in log_indexes:
            txn_in_storage = self.storage.get_all_txn_at(log_index)
            hash1_list.extend(self._generate_hash1_list(log_index, txn_in_storage))
        return hash1_list


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
                round(avg_tree_gen/len(self.history), 4),
                round(avg_h1_prep/len(self.history), 4))

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
