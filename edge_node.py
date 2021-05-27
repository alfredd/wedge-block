import wedgeblock_pb2
import wedgeblock_pb2_grpc

from merklelib import MerkleTree
import merklelib
import hashlib
import pickle


class LogEntry:
    def __init__(self, index, merkle_tree:MerkleTree):
        self.index = index
        self.merkle_tree = merkle_tree

    def __str__(self):
        return str(self.merkle_tree)


class Log:
    def __init__(self):
        self.l = []

    def insert(self, logentry:LogEntry):
        self.l.append(logentry)

    def get_log_entry(self):
        return len(self.l)

    def __str__(self):
        return ", ".join(map(str, self.l))


class EdgeNode():
    def __init__(self):
        self.log = Log()
        self.buffer = []

    def get_txn_from_client(self, txn: wedgeblock_pb2.Transaction) -> wedgeblock_pb2.Hash1:
        # self.buffer.append(str(txn))
        # print(self.buffer)
        # while len(self.buffer) < 2:
        #     pass
        data = (txn.rw.key, txn.rw.val)
        data_list = [data]

        tree = MerkleTree(data_list, EdgeNode.hash_func)   # txn.rw is unhashable without str()
        root = tree.merkle_root

        proof = tree.get_proof(data)
        proof_pickle = pickle.dumps(proof)

        self.log.insert(LogEntry(self.log.get_log_entry(), tree))
        print(self.log)

        hash1 = wedgeblock_pb2.Hash1(logIndex=self.log.get_log_entry()-1, rw=txn.rw,
                                     merkleRoot=root, merkleProof=proof_pickle)
        return hash1

    @staticmethod
    def hash_func(value):
        return hashlib.sha256(value).hexdigest()