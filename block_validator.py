from ropsten_connector import RopEth
from threading import Lock
import ast


class BlockValidator():
    def __init__(self):
        self.r = RopEth()
        # self.l = []
        self.m = Lock()
        pass

    def insert_to_verify(self, txnHash, merkleRoot, logIndex, callback):
        # self.l.append((txnHash, merkleRoot, logIndex, False, callback))
        self.m.acquire()
        self.verify(txnHash, merkleRoot, logIndex, callback)
        self.m.release()

    def verify(self, txnHash, expectedMerkleRoot, expectedLogIndex, callback):
        message = self.r.getInputMessageForTxn(txnHash)
        print(message)
        (merkleroot, logindex) = ast.literal_eval(message)
        callback(txnHash, (expectedMerkleRoot, expectedLogIndex), (merkleroot, logindex))
