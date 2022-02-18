from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from web3.auto import w3
from web3 import Web3
from eth_account.messages import encode_defunct

private_key = ECC.import_key(open('privatekey.der', 'rb').read())
trusted_public_key = ECC.import_key(open('publickey.der', 'rb').read())

signer = DSS.new(private_key, 'fips-186-3')
verifier = DSS.new(trusted_public_key, 'fips-186-3')

# the key pair below is used to sign/verify msg that will be sent to eth network
# the msg will be used to invoke punishment contract if certain conditions met
# represent edge node
PRIVATE_KEY = "412d615056aa890f9dabff07e64169f40e1197152d87b57e3bfccb51fdf02650"
PUBLIC_KEY = "0x7033fA570e6710766536147321ffFf36c9a70CB1"


def sign_eth_msg(index:int, merkle_root:str) -> bytes:
    message_hash = Web3.solidityKeccak(['uint256', 'string'], [index, merkle_root])
    message_hash = encode_defunct(primitive=message_hash)
    signed_message = w3.eth.account.sign_message(message_hash, private_key=PRIVATE_KEY)
    return signed_message.signature


def verify_eth_msg_sig(index:int, merkle_root:str, sig:bytes) -> bool:
    message_hash = Web3.solidityKeccak(['uint256', 'string'], [index, merkle_root])
    message_hash = encode_defunct(primitive=message_hash)
    signer = w3.eth.account.recover_message(message_hash, signature=sig)
    return signer == PUBLIC_KEY
