from web3 import Web3, HTTPProvider
import json
import time
import random

class BaseCaseContract:
    def __init__(self):
        API_URL = "https://eth-ropsten.alchemyapi.io/v2/7vaJ2a1MCsVF9Ft0eRvM5vW-bG4I9xg-"

        # represent edge node
        PRIVATE_KEY = "412d615056aa890f9dabff07e64169f40e1197152d87b57e3bfccb51fdf02650"
        PUBLIC_KEY = "0x7033fA570e6710766536147321ffFf36c9a70CB1"

        # deoployed on Ropsten network
        self.contract_address = "0x38D2A28eaF717123C764058759c743Bb51547CB0"

        self.wallet_private_key = PRIVATE_KEY
        self.wallet_address = PUBLIC_KEY
        self.w3 = Web3(HTTPProvider(API_URL))
        with open('contracts/baseCase.json') as f:
            self.data = json.load(f)
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=self.data["abi"])

    def update(self, keys: [bytes], values: [bytes], sequence_numbers: [int]):
        nonce = self.w3.eth.get_transaction_count(self.wallet_address)
        txn_dict = self.contract.functions.update(keys, values, sequence_numbers).buildTransaction({
            'from': self.wallet_address,
            'nonce': nonce
        })
        sign_promise = self.w3.eth.account.signTransaction(txn_dict, self.wallet_private_key)
        result = self.w3.eth.send_raw_transaction(sign_promise.rawTransaction)
        return result


    def getData(self, key: bytes):
        return self.contract.functions.getData(key).call()

    def getTransactionReceipt(self, txn_hash):
        try:
            response = self.w3.eth.wait_for_transaction_receipt(txn_hash)
            return response
        except Exception as e:
            print(e)
            return None


if __name__ == '__main__':
    base_case_contract = BaseCaseContract()
    # num_of_runs = 10
    # workload_size = 50
    #
    # total_wait_time = 0
    # total_gas = 0
    #
    # key_size = 64
    # value_size = 512
    #
    # for run in range(num_of_runs):
    #     keys = []
    #     values = []
    #     sequence_numbers = []
    #     for i in range(run*workload_size, (run+1)*workload_size):
    #         keys.append(i.to_bytes(key_size, 'big'))
    #         values.append(i.to_bytes(value_size, 'big'))
    #         sequence_numbers.append(i)
    #
    #     print("workload generated")
    #
    #     before_send_out_t = time.perf_counter()
    #
    #     txid = base_case_contract.update(keys, values, sequence_numbers)
    #     receipt = base_case_contract.getTransactionReceipt(txid)
    #     while receipt == None:
    #         print("waiting for txn to be approved")
    #         receipt = base_case_contract.getTransactionReceipt(txid)
    #     after_receipt_received_t = time.perf_counter()
    #     print("received receipt after {} sec.".format(after_receipt_received_t - before_send_out_t))
    #     total_wait_time += after_receipt_received_t - before_send_out_t
    #     print("gas used: ", receipt['gasUsed'])
    #     total_gas += receipt['gasUsed']
    #
    # print("total waiting time: {}".format(total_wait_time))
    # print("total gas used: {}".format(total_gas))

    key_size = 64
    query_keys = random.sample(range(500), 100)

    query_start = time.perf_counter()
    for q_k in query_keys:
        base_case_contract.getData(q_k.to_bytes(key_size, 'big'))
    print("100 queries answered after {} s".format(time.perf_counter() - query_start))