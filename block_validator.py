from hash1_store_contract import Hash1StoreContract
from threading import Lock


class BlockValidator:
    def __init__(self):
        self.contract_connector = Hash1StoreContract()
        self.m = Lock()

    def thread_safe_verify(self, merkle_root, log_index):
        self.m.acquire()
        self.verify(merkle_root, log_index)
        self.m.release()

    def verify(self, expected_merkle_root, expected_log_index):
        root_stored_onchain = self.contract_connector.getRootAtIndex(expected_log_index)
        if expected_merkle_root != root_stored_onchain:
            raise Exception('Hash2 verification failed. Blockchain \
            recorded a different merkle root: {}.'.format(root_stored_onchain))
        #
        #
        # expected_log_index = str(expected_log_index)
        # roots, start_index = self.r.getInputMessageForTxn(txn_hash)
        # # blockchain_record = json.loads(message)
        # target_index = int(expected_log_index) - start_index
        # if 0 <= target_index < len(roots):
        #     recorded_merkle_root = roots[target_index]
        #     if expected_merkle_root != recorded_merkle_root:
        #         raise Exception('Hash2 verification failed. Blockchain transaction {} \
        #         recorded a different merkle root: {}.'.format(txn_hash, recorded_merkle_root))
        # else:
        #     raise Exception('Hash2 verification failed. Blockchain transaction {} \
        #     does not include log index {}.'.format(txn_hash, expected_log_index))
