from web3 import Web3, HTTPProvider
import web3
import json
import datetime

class RopEth():
    def __init__(self):
        API_URL = "https://eth-ropsten.alchemyapi.io/v2/C6WMqDdkePbzxIARHzJ8mUB0lWhZp_nS"
        PRIVATE_KEY = "5244801e4622fa80bd1bb935c14702ee9f20c8435b8d4b22da33bd57a672b7f5"
        PUBLIC_KEY = "0x42Ac97Ca76346F3fDd33BeA61B2ED90649f1a410"
        self.contract_address = "0xD1B428a52ED93e1e5FA4033f1c1334A74FbFa18f"
        self.wallet_private_key = PRIVATE_KEY
        self.wallet_address = PUBLIC_KEY
        self.w3 = Web3(HTTPProvider(API_URL))
        with open('contracts/HelloWorld.json') as f:
            self.data = json.load(f)
            print("Contract ABI: ",self.data["abi"])
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=self.data["abi"])

    def updateContractData(self, data):
        # Executing a transaction.
        nonce = self.w3.eth.get_transaction_count(self.wallet_address)
        message = data
        estimatedGas = self.contract.functions.update(message).estimateGas()
        print("Estimated gas to execute the transaction: ",estimatedGas)
        print(dir(self.contract.functions.update(message)))
        txn_dict = self.contract.functions.update(message).buildTransaction({
            'gas': estimatedGas,
            'from': self.wallet_address,
            'nonce': nonce,
        })
        print(txn_dict)
        print(dir(self.w3.eth.account))
        signPromise = self.w3.eth.account.signTransaction(txn_dict, self.wallet_private_key)
        print(dir(signPromise))
        result = self.w3.eth.send_raw_transaction(signPromise.rawTransaction)
        return result

    def getLatestData(self):
        contract = self.w3.eth.contract(address=self.contract_address, abi=self.data["abi"])
        print(dir(contract.functions))
        v = contract.functions.message().call()
        print("Latest data from contract: ",v)
        return v

    def getTransactionReciept(self, txnHash):
        try:
            response = web3.eth.wait_for_transaction_receipt(web3=self.w3, txn_hash=txnHash, timeout=60, poll_latency=10)
            print(response)
            return response
        except:
            return None
