import asyncio
import logging

import grpc

import wedgeblock_pb2
import wedgeblock_pb2_grpc

from merklelib import MerkleTree
import hashlib


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

        tree = MerkleTree(str(txn), EdgeNode.hash_func)

        proof = tree.get_proof(str(txn))
        proof_list = str(proof)[1:-1].split(", ")  # list of hashes (merkle path)
        merkle_root_hash = proof_list[-1]

        self.log.insert(LogEntry(self.log.get_log_entry(), tree))
        print(self.log)

        hash1 = wedgeblock_pb2.Hash1(logIndex=self.log.get_log_entry()-1, rw = txn.rw)
        return hash1

    @staticmethod
    def hash_func(value):
        return hashlib.sha256(value).hexdigest()