from ropsten_connector import RopEth
from threading import Lock
import json

class BlockValidator():
    def __init__(self):
        self.r = RopEth()
        self.m = Lock()

    def thread_safe_verify(self, txn_hash, merkle_root, log_index):
        self.m.acquire()
        self.verify(txn_hash, merkle_root, log_index)
        self.m.release()

    def verify(self, txn_hash, expected_merkleRoot, expected_logIndex):
        message = self.r.getInputMessageForTxn(txn_hash)
        blockchain_record = json.loads(message)
        if expected_logIndex in blockchain_record:
            recordedMerkleroot = blockchain_record[expected_logIndex]
            if expected_merkleRoot != recordedMerkleroot:
                raise Exception('Hash2 verification failed. Blockchain transaction {} recorded a different merkleroot: {}.'.format(txn_hash, recordedMerkleroot))
        else:
            raise Exception('Hash2 verification failed. Blockchain transaction {} does not include log index {}.'.format(txn_hash, expected_logIndex))
