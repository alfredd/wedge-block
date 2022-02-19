from web3 import Web3, HTTPProvider
import web3
import json
from Crypto.Hash import keccak
import string
from merklelib import MerkleTree
from credential_tools import keccak_hash_func


class Hash1StoreContract:
    def __init__(self):
        API_URL = "https://eth-ropsten.alchemyapi.io/v2/7vaJ2a1MCsVF9Ft0eRvM5vW-bG4I9xg-"

        # represent edge node
        PRIVATE_KEY = "412d615056aa890f9dabff07e64169f40e1197152d87b57e3bfccb51fdf02650"
        PUBLIC_KEY = "0x7033fA570e6710766536147321ffFf36c9a70CB1"

        # deoployed on Ropsten network
        self.contract_address = "0x85bae3688D946D93ed4A31F6E2F60eD74C6035ba"

        self.wallet_private_key = PRIVATE_KEY
        self.wallet_address = PUBLIC_KEY
        self.w3 = Web3(HTTPProvider(API_URL))
        with open('contracts/hash1storage.json') as f:
            self.data = json.load(f)
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=self.data["abi"])

    def update(self, new_merkle_roots: [bytes], start_index: int):
        nonce = self.w3.eth.get_transaction_count(self.wallet_address)
        txn_dict = self.contract.functions.update(new_merkle_roots, start_index).buildTransaction({
            'from': self.wallet_address,
            'nonce': nonce
        })
        sign_promise = self.w3.eth.account.signTransaction(txn_dict, self.wallet_private_key)
        result = self.w3.eth.send_raw_transaction(sign_promise.rawTransaction)
        return result

    def getRootAtIndex(self, index: int):
        return self.contract.functions.getRootAtIndex(index).call()

    def getTransactionReceipt(self, txn_hash):
        try:
            response = web3.eth.wait_for_transaction_receipt(
                web3=self.w3, txn_hash=txn_hash, timeout=60, poll_latency=10)
            return response
        except:
            return None


if __name__ == '__main__':
    hash1_store = Hash1StoreContract()

    # a list of all ASCII letters
    key = list(string.ascii_letters)
    val = list(map(lambda x: (10 * x).encode(), key))
    seq = list(range(len(key)))

    data = list(zip(key, val, seq))

    tree = MerkleTree(data, keccak_hash_func)
    print(type(tree.merkle_root.encode()))

    # txid = hash1_store.update([tree.merkle_root.encode()], 0)
    # receipt = hash1_store.getTransactionReceipt(txid)
    # while receipt == None:
    #     print("waiting for txn to be approved")
    #     receipt = hash1_store.getTransactionReceipt(txid)
    # print("received receipt.")
    # print(receipt)
    #
    print(hash1_store.getRootAtIndex(0))
