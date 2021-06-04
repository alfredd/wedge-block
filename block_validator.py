from ropsten_connector import RopEth
from threading import Lock
import ast
import pickle
import codecs


class BlockValidator():
    def __init__(self):
        self.r = RopEth()
        self.m = Lock()
        pass

    def insert_to_verify(self, txnHash, merkleRoot, logIndex, callback):
        self.m.acquire()
        self.verify(txnHash, merkleRoot, logIndex, callback)
        self.m.release()

    def verify(self, txnHash, expectedMerkleRoot, expectedLogIndex, callback):
        message = self.r.getInputMessageForTxn(txnHash)
        blockchain_record = pickle.loads(codecs.decode(message.encode(), "base64"))
        logindex = None
        merkleroot = None
        if expectedLogIndex in blockchain_record:
            logindex = expectedLogIndex
            merkleroot = blockchain_record[expectedLogIndex]
        callback(txnHash, (expectedMerkleRoot, expectedLogIndex), (merkleroot, logindex))
