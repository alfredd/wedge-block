from web3 import Web3, HTTPProvider
import web3
import json

class RopEth():
    def __init__(self):
        API_URL = "https://eth-ropsten.alchemyapi.io/v2/7vaJ2a1MCsVF9Ft0eRvM5vW-bG4I9xg-"
        PRIVATE_KEY = "412d615056aa890f9dabff07e64169f40e1197152d87b57e3bfccb51fdf02650"
        PUBLIC_KEY = "0x7033fA570e6710766536147321ffFf36c9a70CB1"
        self.contract_address = "0x92C53CC2068eEfC78D724F5F7a75D3f37F082475"
        self.wallet_private_key = PRIVATE_KEY
        self.wallet_address = PUBLIC_KEY
        self.w3 = Web3(HTTPProvider(API_URL))
        with open('contracts/Wedgeblock.json') as f:
            self.data = json.load(f)
            # print("Contract ABI: ",self.data["abi"])
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=self.data["abi"])

    def updateContractData(self, data:[str], startIndex:int, endIndex:int):
        # Executing a transaction.
        nonce = self.w3.eth.get_transaction_count(self.wallet_address)
        estimatedGas = self.contract.functions.update(data, startIndex, endIndex).estimateGas()
        # print("Estimated gas to execute the transaction: ",estimatedGas)
        # print(dir(self.contract.functions.update(message)))
        txn_dict = self.contract.functions.update(data, startIndex, endIndex).buildTransaction({
            'gas': estimatedGas,
            'from': self.wallet_address,
            'nonce': nonce,
        })
        # print(txn_dict)
        # print(dir(self.w3.eth.account))
        signPromise = self.w3.eth.account.signTransaction(txn_dict, self.wallet_private_key)
        # print(dir(signPromise))
        result = self.w3.eth.send_raw_transaction(signPromise.rawTransaction)
        return result

    def getLatestData(self):
        if not self.contract:
            return None
        return self.contract.functions.get().call()

    def getTransactionReceipt(self, txnHash):
        try:
            response = web3.eth.wait_for_transaction_receipt(web3=self.w3, txn_hash=txnHash, timeout=60, poll_latency=10)
            # print(response)
            return response
        except:
            return None
    #
    def getInputMessageForTxn(self, txnHash):
        txn = self.w3.eth.get_transaction(txnHash)
        # print("Txn: ", txn.input)
        decoded = self.w3.eth.contract(self.contract_address, abi=self.data["abi"]).decode_function_input(
            txn.input)
        roots = decoded[1]["newMerkleRoots"]
        startIndex = decoded[1]["startIndex"]
        return roots, startIndex


# ropEth = RopEth()
# txid = ropEth.updateContractData(['0x123456'], 0, 0)
# receipt = ropEth.getTransactionReceipt(txid)
# while receipt == None:
#     receipt = ropEth.getTransactionReceipt(txid)
# print("received receipt.")
# # print(receipt)
#
# m = ropEth.getInputMessageForTxn(txid)
# print(m[0].hex())
# # print("get contract value")
# # print(ropEth.getLatestData())

