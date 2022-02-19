from web3 import Web3, HTTPProvider
from web3.auto import w3
import web3
import json
from eth_account.messages import encode_defunct
import eth_abi


class keccakTestContract:
    def __init__(self):
        API_URL = "https://eth-ropsten.alchemyapi.io/v2/7vaJ2a1MCsVF9Ft0eRvM5vW-bG4I9xg-"

        # represent client node
        PRIVATE_KEY = "392c4950dacd8c5f5070b3911e459b9c9d4a35c67b593d08d70dc7692d09ba55"
        PUBLIC_KEY = "0x18e2de8cf06497D1398a123E6FBa4f37e6170cb2"

        # deoployed on Ropsten network
        self.contract_address = "0x16e07f2FB9d07dcA12849f96F295aC1DE9e0E681"

        self.wallet_private_key = PRIVATE_KEY
        self.wallet_address = PUBLIC_KEY
        self.w3 = Web3(HTTPProvider(API_URL))
        with open('contracts/keccakTest.json') as f:
            self.data = json.load(f)
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=self.data["abi"])

    def invokePunishment(self, index: int, merkle_root: bytes, merkle_path: [bytes],
                         merkle_path_dir: [int], raw_txn_str: str, signature: bytes):
        nonce = self.w3.eth.get_transaction_count(self.wallet_address)
        txn_dict = self.contract.functions.invokePunishment(
            index, merkle_root, merkle_path,merkle_path_dir, raw_txn_str, signature).buildTransaction(
        {
            'from': self.wallet_address,
            'nonce': nonce
        })
        sign_promise = self.w3.eth.account.signTransaction(txn_dict, self.wallet_private_key)
        result = self.w3.eth.send_raw_transaction(sign_promise.rawTransaction)
        return result

    def getTransactionReceipt(self, txn_hash):
        try:
            response = web3.eth.wait_for_transaction_receipt(
                web3=self.w3, txn_hash=txn_hash, timeout=60, poll_latency=10)
            return response
        except:
            return None


if __name__ == '__main__':
    punishment_contract = keccakTestContract()

    # represent edge
    PRIVATE_KEY = "412d615056aa890f9dabff07e64169f40e1197152d87b57e3bfccb51fdf02650"
    PUBLIC_KEY = "0x7033fA570e6710766536147321ffFf36c9a70CB1"

    # the correct root at index 0
    # c1fa082b1e9639f09428be63228a2d745fba22b6bc6edf7a5ef6f225fc04ba90

    index = 0
    merkle_root = b'T[\x06\xfe\xb6\xb3d\xb6\xc3\x95\xb6\xf9\xa6s\xb0\xdc\xe5\xa8C\x94\xdc\xe1\xe6\xdfV\xee\x17\x02\x01\xfa{\x87'
    merkle_path = [b'I\xfc\xdfk\xdf\xd5\x97\xcf;\x18p\xdf~|hb\xc6\xe7\x0e\x006R\x0f\xb6\xd5\xb4\xda\xe2[\x1e\xd7\xa6', b'\xdbN\xc6em\xd8\xf8O:\xe9G\xa9\x08n\xc4j%\xd2\x13Od\xb2(xb\xbd,YJo\x98\x11', b'\x05\x0b\xb7\xa7k\xd2\t\xf8|\xf8sN\xfb\x07[\x84\xe7\xeaW)zcu\xb1\x18D=\xf4\xab\xce\xa1\xf3', b"u\xa4\x8c\x7f\xd9\xda\xad$\x1f\xcd'\xb5\x9e\x9a\x1c\x9f55M\xf4\xe4\x88\x1fj\x8b\x1c\xa8v\xd0\xff\xc4\x0b", b'9\x9e\xcc\xdb\x868\xca/\xbc\xc9\xff\x88dW\xfe\x83q\x02\xda"\xb2\xecKN"\xa3\xe0\xe1Y\x11\x1d\x12', b'\x1d\\\rY\t\x90\x06\x17\x16\xb7\x95& \xdc\r\x05\x95\xf2\x9d>\xaa\x14/`q\xe0+\xf0\xd6\x83\r\xc7', b'J\xfdHg|H\x85\xb8,[\x9b\xf1\xec\xe5\x81\xc0\x86\xf1\xf5o\t\x9b\xecX\x82\xd4\xdd\x06q\x97-\xad']
    merkle_path_dir = [1, 1, 0, 0, 0, 1, 1]
    raw_txn_str = "(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c', b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c', 28)"

    expected_sig = b'\xc9\xe0p\x84\x9f\xba\x03\r\x0b*\xfb\x0b\xb1F^\xeau\x08\x97\xe1\xcf\xe8;\x05\x1387/\xb4\x134#,vM\x89\xa8Z\x86\x8e~\x1fN\xae\xca\xbc\xb4[\xbfO\x7f.\xec\xb3\xe5S\x08(\n\xbam\x9d\x8e\xa6\x1c'


    abiEncoded = eth_abi.encode_abi(['uint256', 'bytes', 'bytes[]', 'uint256[]', 'string'],
                                    [index, merkle_root, merkle_path, merkle_path_dir, raw_txn_str])
    message_hash = w3.solidityKeccak(['bytes'], ['0x' + abiEncoded.hex()])

    # message_hash = Web3.solidityKeccak(['uint256', 'bytes', 'bytes[]', 'uint256[]', 'string'],
    #                                    [index, merkle_root, merkle_path, merkle_path_dir, raw_txn_str])

    message_hash = encode_defunct(primitive=message_hash)
    signed_message = w3.eth.account.sign_message(message_hash, private_key=PRIVATE_KEY)

    print(signed_message.signature)

    result = punishment_contract.invokePunishment(index, merkle_root, merkle_path, merkle_path_dir, raw_txn_str, signed_message.signature)
    print(result.hex())