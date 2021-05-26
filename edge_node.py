import asyncio
import logging

import grpc

import wedgeblock_pb2
import wedgeblock_pb2_grpc

from merklelib import MerkleTree, beautify
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


class EdgeNode(wedgeblock_pb2_grpc.EdgeNodeServicer):
    def __init__(self):
        self.log = Log()

    def Execute(self, txn: wedgeblock_pb2.Transaction, unused_context) -> wedgeblock_pb2.Hash1:
        tree = MerkleTree(str(txn), EdgeNode.hash_func)

        proof = tree.get_proof(str(txn))
        proof_list = str(proof)[1:-1].split(", ")  # list of hashes (merkle path)
        merkle_root_hash = proof_list[-1]

        self.log.insert(LogEntry(self.log.get_log_entry(), tree))
        print(self.log)

        hash1 = wedgeblock_pb2.Hash1(logIndex=0, rw = txn.rw)
        return hash1

    @staticmethod
    def hash_func(value):
        return hashlib.sha256(value).hexdigest()
    #
    # def get_txn_from_client(self, txn):
    #     tree = MerkleTree(txn, self.hashfunc)
    #
    #     proof = tree.get_proof(txn)
    #     proof_list = str(proof)[1:-1].split(", ") # list of hashes (merkle path)
    #     #
    #     # if tree.verify_leaf_inclusion(txn, proof):
    #     #     print('A is in the tree')
    #     # else:
    #     #     print('A is not in the tree')
    #
    #     return proof_list

async def serve() -> None:
    server = grpc.aio.server()
    wedgeblock_pb2_grpc.add_EdgeNodeServicer_to_server(EdgeNode(), server)
    server.add_insecure_port('[::]:50051')
    await server.start()
    await server.wait_for_termination()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.get_event_loop().run_until_complete(serve())