from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from web3.auto import w3
from web3 import Web3
from eth_account.messages import encode_defunct
import eth_abi
import time
import wedgeblock_pb2 as wb
import pickle
from Crypto.Hash import keccak
import merklelib


private_key = ECC.import_key(open('privatekey.der', 'rb').read())
trusted_public_key = ECC.import_key(open('publickey.der', 'rb').read())

signer = DSS.new(private_key, 'fips-186-3')
verifier = DSS.new(trusted_public_key, 'fips-186-3')


def keccak_hash_func(value):
    return keccak.new(data=value, digest_bits=256).hexdigest()

# the key pair below is used to sign/verify msg that will be sent to eth network
# the msg will be used to invoke punishment contract if certain conditions met
# represent edge node
PRIVATE_KEY = "412d615056aa890f9dabff07e64169f40e1197152d87b57e3bfccb51fdf02650"
PUBLIC_KEY = "0x7033fA570e6710766536147321ffFf36c9a70CB1"


def sign_eth_msg(index:int, merkle_root:bytes, merkle_path:[bytes], merkle_path_dir:[int], raw_txn_str:str) -> bytes:
    abiEncoded = eth_abi.encode_abi(['uint256', 'bytes', 'bytes[]', 'uint256[]', 'string'],
                                    [index, merkle_root, merkle_path, merkle_path_dir, raw_txn_str])
    message_hash = w3.solidityKeccak(['bytes'], ['0x' + abiEncoded.hex()])

    # message_hash = Web3.solidityKeccak(['uint256', 'bytes', 'bytes[]', 'uint256[]', 'string'],
    #                                    [index, merkle_root, merkle_path, merkle_path_dir, raw_txn_str])

    message_hash = encode_defunct(primitive=message_hash)
    signed_message = w3.eth.account.sign_message(message_hash, private_key=PRIVATE_KEY)
    return signed_message.signature


def verify_eth_msg_sig(index:int, merkle_root:bytes, merkle_path:[bytes],
                       merkle_path_dir:[int], raw_txn_str:str, sig:bytes) -> bool:
    abiEncoded = eth_abi.encode_abi(['uint256', 'bytes', 'bytes[]', 'uint256[]', 'string'],
                                    [index, merkle_root, merkle_path, merkle_path_dir, raw_txn_str])
    message_hash = w3.solidityKeccak(['bytes'], ['0x' + abiEncoded.hex()])
    # message_hash = Web3.solidityKeccak(['uint256', 'bytes', 'bytes[]', 'uint256[]', 'string'],
    #                                    [index, merkle_root, merkle_path, merkle_path_dir, raw_txn_str])
    message_hash = encode_defunct(primitive=message_hash)
    signer = w3.eth.account.recover_message(message_hash, signature=sig)
    return signer == PUBLIC_KEY


def verify_hash1_response(hash1_response: wb.Hash1Response, original_transaction=None):
    # verify the signature is correct
    sig_verify_start = time.perf_counter()
    # verify eth msg signature is correct
    hash1 = hash1_response.h1
    eth_msg_verified = verify_eth_msg_sig(hash1.logIndex, hash1.merkleRoot,
                                          hash1.merkleProofPath, hash1.merkleProofDir,
                                          hash1.rawTxnStr,
                                          hash1_response.ethMsgSignature)
    if not eth_msg_verified:
        return False, 0, 0

    sig_verify_time = time.perf_counter() - sig_verify_start

    # verify the merkle proof is correct
    tree_inclusion_verify_start = time.perf_counter()

    merkle_proof = pickle.loads(hash1.merkleProof)  # deserialize
    # data to be verified
    if original_transaction is not None:
        raw_txn_data = (original_transaction.key, original_transaction.val, original_transaction.sequenceNumber)
    else:
        raw_txn_data = (hash1.key, hash1.val, hash1.sequenceNumber)
    # look into verify_leaf_inclusion, actually var data should be properly hashed before feeding into this function
    # if not, the function still works fine but it is NOT optimized!
    if not merklelib.verify_leaf_inclusion(raw_txn_data, merkle_proof, keccak_hash_func, hash1.merkleRoot):
        return False, 0, 0

    tree_inclusion_verify_time = time.perf_counter() - tree_inclusion_verify_start

    return True, sig_verify_time, tree_inclusion_verify_time
