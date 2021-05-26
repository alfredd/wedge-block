# wedge-block

# Edge node:
## Implement blockchain (part of edge node)
* Merkle Tree (https://github.com/vpaliy/merklelib) => Yinan
  * Insert txn
  * Get proof
* Logs
* Get txn from client => Abhishek
  * Protobuf for txn
* Serialize transactions in to batches
* Write to blockchain
* Get H1
* Phase 1 Commit
* Respond to client with H1
* Phase 2 Commit
* Send H1 to Ethereum smart contract
* Get H2.
* Add H2 to corresponding log entry (certified by Ethereum blockchain)
* Send H2 to Client
## Ethereum smart contract (Yinan)
* Get H1
* Sign H1 generate H1Signed
* Respond with Txn Hash = H2
# Client 
* Create txn,
* Send txn to Edge node. Get H1
* Wait for H2
* Verify H2 on Ethereum blockchain


# Dependencies
* Protobuf and gRPC
  >  `pip install grpcio`

  >  `pip install grpcio-tools`

* merklelib
  > `pip install merklelib`