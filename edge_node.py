import wedgeblock_pb2
import wedgeblock_pb2_grpc

from merklelib import MerkleTree
import merklelib
import hashlib
import pickle
import threading
import time


class LogEntry:
    def __init__(self, index, merkle_tree:MerkleTree):
        self.index = index
        self.merkle_tree = merkle_tree

    def __str__(self):
        return str(self.merkle_tree)


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
        return ", ".join(map(str, self.l))


class EdgeNode():
    def __init__(self):
        self.log = Log()
        self.buffer = []
        self.buffer_check_interval = 10 # seconds

        buffer_check_thread = threading.Thread(target=self.scheduled_buffer_check, daemon=True)
        buffer_check_thread.start()
        self.log_added_event = threading.Event()

    def scheduled_buffer_check(self):
        while True:
            time.sleep(self.buffer_check_interval)
            if len(self.buffer) > 0:
                self.process_batch()

    def process_batch(self):
        tree = MerkleTree(self.buffer, self.hash_func)
        self.log.insert(LogEntry(self.log.get_next_log_index(), tree))
        self.log_added_event.set()
        self.buffer = []
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

        log_index = self.log.get_log_entry(target_index).index
        assert log_index == target_index
        tree = self.log.get_log_entry(target_index).merkle_tree
        root = tree.merkle_root
        proof = tree.get_proof(data)
        assert merklelib.verify_leaf_inclusion(data, proof, self.hash_func, root)
        proof_pickle = pickle.dumps(proof)

        hash1 = wedgeblock_pb2.Hash1(rw=txn.rw, merkleRoot=root, merkleProof=proof_pickle)
        hash1.logIndex = target_index  # when logIndex is 0, this field will not be included in hash1. why????
        return hash1

    @staticmethod
    def hash_func(value):
        return hashlib.sha256(value).hexdigest()