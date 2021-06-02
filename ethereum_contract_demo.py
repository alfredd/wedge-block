# import web3
from web3 import Web3, HTTPProvider
import web3
import json
import binascii
import time, datetime

class DemoRopEth():
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
        message = "WedgeBlock Says Hi! @ %s" % datetime.datetime.now().strftime("%H:%M:%S")
        estimatedGas = self.contract.functions.update(message).estimateGas()
        print(estimatedGas)
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
            txn = self.w3.eth.get_transaction(txnHash)
            print("Txn: ", txn.input)
            decoded = self.w3.eth.contract(self.contract_address, abi=self.data["abi"]).decode_function_input(
                txn.input)
            message_ = decoded[1]["newMessage"]
            print("data: ", message_)
            return response
        except:
            return None

def main():
    API_URL = "https://eth-ropsten.alchemyapi.io/v2/C6WMqDdkePbzxIARHzJ8mUB0lWhZp_nS"
    PRIVATE_KEY = "5244801e4622fa80bd1bb935c14702ee9f20c8435b8d4b22da33bd57a672b7f5"
    PUBLIC_KEY = "0x42Ac97Ca76346F3fDd33BeA61B2ED90649f1a410"
    contract_address = "0xD1B428a52ED93e1e5FA4033f1c1334A74FbFa18f"
    wallet_private_key = PRIVATE_KEY
    wallet_address = PUBLIC_KEY
    w3 = Web3(HTTPProvider(API_URL))
    with open('contracts/HelloWorld.json') as f:
        data = json.load(f)
        print(data["abi"])
        contract = w3.eth.contract(address=contract_address, abi=data["abi"])
        print(dir(contract.functions))
        v = contract.functions.message().call()
        print(v)

        # Executing a transaction.
        nonce = w3.eth.get_transaction_count(wallet_address)
        message = "WedgeBlock Says Hi! @ %s" %datetime.datetime.now().strftime("%H:%M:%S")
        estimatedGas = contract.functions.update(message).estimateGas()
        print(estimatedGas)
        print(dir(contract.functions.update(message)))
        txn_dict = contract.functions.update(message).buildTransaction({
            'gas': estimatedGas,
            'from': wallet_address,
            'nonce': nonce,
        })
        print(txn_dict)
        print(dir(w3.eth.account))
        signPromise = w3.eth.account.signTransaction(txn_dict, wallet_private_key)
        print(dir(signPromise))
        result = w3.eth.send_raw_transaction(signPromise.rawTransaction)

        print("Result of executing the signed transaction: ",binascii.hexlify(result))

        # tx_receipt = None
        # count = 0
        # while tx_receipt is None and (count < 30):
        #     time.sleep(10)
        #
        #     tx_receipt = w3.eth.getTransactionReceipt(result)
        #
        #     print(tx_receipt)
        #     type(tx_receipt)
        #     print(tx_receipt["transactionHash"])
        return result
def verify_txn_hash(result):
    try:
        response = web3.eth.wait_for_transaction_receipt(txn_hash=result, timeout=60, poll_latency=10)
        print(response)
        return response
    except:
        return None

def thrd(reth:DemoRopEth, data, counter):
    print("Executing thread:", counter)
    res = reth.updateContractData(data)
    print("thread result: ", counter,", Txn hash: ", binascii.hexlify(res))

if __name__ == '__main__':
    # txnHash = main()
    # time.sleep(120)
    reth = DemoRopEth()

    # import threading
    # teth=[]
    # for i in range(1,5):
    #     t = threading.Thread(target=thrd, args=(reth,datetime.datetime.now().strftime("%H:%M:%S"), i))
    #     teth.append(t)
    #     time.sleep(1)
    # for thread in teth:
    #     thread.start()
    # for thread in teth:
    #     thread.join()
    txnHash = b'9f953eac9a716e1e5e90400195cb25f606cf0224a9bf947054cf4ce75a771a83'
    t = binascii.unhexlify(txnHash)
    reciept = reth.getTransactionReciept(t)
    print("Txn receipt", reciept)
    if reciept == None:
        print("Txn with hash %s not found on the blockchain." %txnHash)
    print(reth.getLatestData())