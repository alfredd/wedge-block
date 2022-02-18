import time
from concurrent.futures.thread import ThreadPoolExecutor

import wedgeblock_pb2_grpc as wbgrpc
import wedgeblock_pb2 as wb
import grpc
import edge_node

import logging

from Crypto.Hash import SHA256

import multiprocessing as mp

from credential_tools import signer, verifier, sign_eth_msg


def verify_sig(raw_bytes, signature):
    # verify the signature is correct
    sig_verify_start = time.perf_counter()
    txn_hash = SHA256.new(raw_bytes)
    try:
        verifier.verify(txn_hash, signature)
    except ValueError:
        return False, 0
    sig_verify_time = time.perf_counter() - sig_verify_start
    return True, sig_verify_time


def sign_response(h1: wb.Hash1):
    if h1 is None:
        return None
    eth_msg_signature = sign_eth_msg(h1.logIndex, h1.merkleRoot)
    response_content_hash = SHA256.new(h1.SerializeToString())
    response_signature = signer.sign(response_content_hash)
    return wb.Hash1Response(h1=h1, ethMsgSignature= eth_msg_signature, responseSignature=response_signature)


class EdgeService(wbgrpc.EdgeNodeServicer):
    def __init__(self):
        self.edge_node = edge_node.EdgeNode()
        self.batch_size = 1000
        self.total_service_time = 0

    def _sign_hash1_list(self, hash1_list: [wb.Hash1], pool):
        # sign a list of hash1 in parallel
        # pool = mp.Pool(mp.cpu_count())
        result_objects = []
        for h1 in hash1_list:
            result_objects.append(pool.apply_async(sign_response, args=(h1,)))
        signed_hash1_list = [r.get() for r in result_objects]
        # pool.close()
        # pool.join()

        return signed_hash1_list


    def Execute(self, request: wb.Transaction, context):
        raise NotImplementedError

    def ExecuteBatch(self, request: [wb.Transaction], context):
        function_start = time.perf_counter()
        workload_size = len(request.content)

        # verify all signatures are correct (parallel)
        pool = mp.Pool(mp.cpu_count())
        result_objects = []

        sig_verification_start_t = time.perf_counter()
        for txn in request.content:
            result_objects.append(pool.apply_async(
                verify_sig,
                args=(txn.rw.SerializeToString() + str(txn.sequenceNumber).encode(), txn.signature,))
            )
        verification_results = [r.get() for r in result_objects]

        total_sig_verify_t = 0
        for v_result in verification_results:
            try:
                assert v_result[0]
            except AssertionError:
                print("Verification Failed")
            total_sig_verify_t += v_result[1]

        print("Total time on signature verification (parallel): ",
              round(time.perf_counter() - sig_verification_start_t, 4))
        print("Avg time each txn on signature verification: ", round(total_sig_verify_t / workload_size, 4))

        batch_time_avg = 0
        batch_signing_avg = 0
        batch_n = 0
        for batch_n in range(workload_size//self.batch_size + 1):
            batch = request.content[batch_n*self.batch_size:(batch_n+1)*self.batch_size]
            if len(batch) == 0:
                batch_n -= 1
                break

            batch_begin = time.perf_counter()
            # process the txn batch to get h1 batch
            h1_result = self.edge_node.process_txn_batch(batch)

            # signing the h1 batch (in parallel)
            signing_start = time.perf_counter()

            batch_response = self._sign_hash1_list(h1_result, pool)

            batch_signing_avg += time.perf_counter() - signing_start
            batch_time_avg += time.perf_counter() - batch_begin

            for response in batch_response:
                yield response

        pool.close()
        pool.join()

        print(self.edge_node.analyser.get_avg_record())
        print("Avg time per batch (h1_sign): ", round(batch_signing_avg / (batch_n + 1), 4))
        print("Avg time per batch (total): ", round(batch_time_avg/(batch_n + 1), 4))
        print("ExecuteBatch Completed\n")

        function_end = time.perf_counter()
        self.total_service_time += function_end - function_start
        print("[EdgeNode (H1): ]Total Service time so far: ", round(self.total_service_time, 4))

    def GetPhase2Hash(self, request: wb.LogHash, context):
        if not self.edge_node.entry_exist_at_index(request.logIndex):
            return wb.Hash2(status=wb.Hash2Status.INVALID)
        h2 = self.edge_node.get_h2_at_index(request.logIndex)
        if h2 is not None:
            return wb.Hash2(TxnHash=h2, status=wb.Hash2Status.VALID)
        return wb.Hash2(status=wb.Hash2Status.NOT_READY)

    def AnswerQuery(self, query: wb.QueryBatch, context):
        h1_result = self.edge_node.answer_query(query.keys)

        pool = mp.Pool(mp.cpu_count())
        batch_response = self._sign_hash1_list(h1_result, pool)
        pool.close()
        pool.join()

        for response in batch_response:
            yield response

    def AnswerFullLogAudit(self, audit_request: wb.AuditRequest, context):
        h1_result = self.edge_node.answer_full_log_query(audit_request.logIndexes)
        pool = mp.Pool(mp.cpu_count())
        batch_response = self._sign_hash1_list(h1_result, pool)
        pool.close()
        pool.join()
        for response in batch_response:
            yield response


def serve():
    options = [('grpc.max_receive_message_length', 1024 * 1024 * 1024),
               ('grpc.http2.max_ping_strikes', 0)]
    server = grpc.server(ThreadPoolExecutor(max_workers=10), options=options)
    wbgrpc.add_EdgeNodeServicer_to_server(
        EdgeService(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    logging.basicConfig()
    serve()
