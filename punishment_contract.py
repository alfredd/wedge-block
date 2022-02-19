from web3 import Web3, HTTPProvider
from web3.auto import w3
import web3
import json
from eth_account.messages import encode_defunct


class PunishmentContract:
    def __init__(self):
        API_URL = "https://eth-ropsten.alchemyapi.io/v2/7vaJ2a1MCsVF9Ft0eRvM5vW-bG4I9xg-"

        # represent client node
        PRIVATE_KEY = "392c4950dacd8c5f5070b3911e459b9c9d4a35c67b593d08d70dc7692d09ba55"
        PUBLIC_KEY = "0x18e2de8cf06497D1398a123E6FBa4f37e6170cb2"

        # deoployed on Ropsten network
        self.contract_address = "0x2EA3b7E672358eA7Ac5f572c90b29427e897a697"

        self.wallet_private_key = PRIVATE_KEY
        self.wallet_address = PUBLIC_KEY
        self.w3 = Web3(HTTPProvider(API_URL))
        with open('contracts/punishment.json') as f:
            self.data = json.load(f)
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=self.data["abi"])

    def invokePunishment(self, index: int, root: str, signature: bytes):
        # result = self.contract.functions.invokePunishment(index, root, signature).call()
        nonce = self.w3.eth.get_transaction_count(self.wallet_address)
        txn_dict = self.contract.functions.invokePunishment(index, root, signature).buildTransaction({
            'from': self.wallet_address,
            'nonce': nonce
        })
        sign_promise = self.w3.eth.account.signTransaction(txn_dict, self.wallet_private_key)
        result = self.w3.eth.send_raw_transaction(sign_promise.rawTransaction)
        return result

    def update(self, new_merkle_roots: [str], start_index: int):
        nonce = self.w3.eth.get_transaction_count(self.wallet_address)
        txn_dict = self.contract.functions.update(new_merkle_roots, start_index).buildTransaction({
            'from': self.wallet_address,
            'nonce': nonce
        })
        sign_promise = self.w3.eth.account.signTransaction(txn_dict, self.wallet_private_key)
        result = self.w3.eth.send_raw_transaction(sign_promise.rawTransaction)
        return result

    def getRootAtIndex(self, index:int):
        return self.contract.functions.getRootAtIndex(index).call()

    def getTransactionReceipt(self, txn_hash):
        try:
            response = web3.eth.wait_for_transaction_receipt(
                web3=self.w3, txn_hash=txn_hash, timeout=60, poll_latency=10)
            return response
        except:
            return None


if __name__ == '__main__':
    punishment_contract = PunishmentContract()

    # represent edge
    PRIVATE_KEY = "412d615056aa890f9dabff07e64169f40e1197152d87b57e3bfccb51fdf02650"
    PUBLIC_KEY = "0x7033fA570e6710766536147321ffFf36c9a70CB1"

    # the correct root at index 0
    # c1fa082b1e9639f09428be63228a2d745fba22b6bc6edf7a5ef6f225fc04ba90

    message_hash = Web3.solidityKeccak(['uint256', 'string'], [0, "c1fa082b1e9639f09428be63228a2d745fba22b6bc6edf7a5ef6f225fc04ba90"])
    message_hash = encode_defunct(primitive=message_hash)
    signed_message = w3.eth.account.sign_message(message_hash, private_key=PRIVATE_KEY)

    result = punishment_contract.invokePunishment(0, "c1fa082b1e9639f09428be63228a2d745fba22b6bc6edf7a5ef6f225fc04ba90", signed_message.signature)
    print(result.hex())