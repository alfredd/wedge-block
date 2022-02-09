from web3 import Web3, HTTPProvider
import web3
import json

from web3.exceptions import TimeExhausted


class PayableContract:
    def __init__(self):
        API_URL = "https://eth-ropsten.alchemyapi.io/v2/7vaJ2a1MCsVF9Ft0eRvM5vW-bG4I9xg-"

        using_account1 = False

        if using_account1:
            # Account 1
            PRIVATE_KEY = "412d615056aa890f9dabff07e64169f40e1197152d87b57e3bfccb51fdf02650"
            PUBLIC_KEY = "0x7033fA570e6710766536147321ffFf36c9a70CB1"
        else:
            # Account 2
            PRIVATE_KEY = "392c4950dacd8c5f5070b3911e459b9c9d4a35c67b593d08d70dc7692d09ba55"
            PUBLIC_KEY = "0x18e2de8cf06497D1398a123E6FBa4f37e6170cb2"

        self.contract_address = "0x2e8816ddCC3209F0A072Fe9E2C3e8299A04626eE"

        self.wallet_private_key = PRIVATE_KEY
        self.wallet_address = PUBLIC_KEY
        self.w3 = Web3(HTTPProvider(API_URL))
        with open('contracts/payable_contract.json') as f:
            self.data = json.load(f)
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=self.data["abi"])

    def deposit(self, amount: int):
        nonce = self.w3.eth.get_transaction_count(self.wallet_address)
        estimate_gas = self.contract.functions.deposit().estimateGas()
        # print("Estimated gas to execute the transaction: ",estimate_gas)
        # print(dir(self.contract.functions.update(message)))
        txn_dict = self.contract.functions.deposit().buildTransaction({
            'gas': estimate_gas,
            'from': self.wallet_address,
            'nonce': nonce,
            'value': amount
        })
        # print(txn_dict)
        # print(dir(self.w3.eth.account))
        sign_promise = self.w3.eth.account.signTransaction(txn_dict, self.wallet_private_key)
        # print(dir(sign_promise))
        result = self.w3.eth.send_raw_transaction(sign_promise.rawTransaction)
        return result

    def withdraw(self):
        nonce = self.w3.eth.get_transaction_count(self.wallet_address)
        estimate_gas = self.contract.functions.withdraw().estimateGas()
        # print("Estimated gas to execute the transaction: ",estimate_gas)
        # print(dir(self.contract.functions.update(message)))
        txn_dict = self.contract.functions.withdraw().buildTransaction({
            'gas': estimate_gas,
            'from': self.wallet_address,
            'nonce': nonce,
        })
        # print(txn_dict)
        # print(dir(self.w3.eth.account))
        sign_promise = self.w3.eth.account.signTransaction(txn_dict, self.wallet_private_key)
        # print(dir(sign_promise))
        result = self.w3.eth.send_raw_transaction(sign_promise.rawTransaction)
        return result

    def get_transaction_receipt(self, txn_hash):
        try:
            response = web3.eth.wait_for_transaction_receipt(web3=self.w3, txn_hash=txn_hash,
                                                             timeout=60, poll_latency=10)
            # print(response)
            return response
        except TimeExhausted:
            return None


payableContract = PayableContract()
# tx_id = payableContract.deposit(10**18)
tx_id = payableContract.withdraw()
receipt = payableContract.get_transaction_receipt(tx_id)
while receipt is None:
    receipt = payableContract.get_transaction_receipt(tx_id)
print("received receipt.")
print(receipt)


# m = ropEth.getInputMessageForTxn(tx_id)
# print(m[0].hex())
# # print("get contract value")
# # print(ropEth.getLatestData())
