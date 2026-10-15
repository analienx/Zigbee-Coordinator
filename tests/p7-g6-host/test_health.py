#!/usr/bin/env python3
"""Offline health contracts and injected-owner probes; no device or socket."""
import asyncio
import importlib.util
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("p7u_health",ROOT/"deploy/p7u_health.py")
health=importlib.util.module_from_spec(spec);spec.loader.exec_module(health)

# Actual compiled recorder/MT handler output from the pinned-source C regression,
# independently decoded here; this includes changed RAM defaults 0/0/3/10.
C_HEALTH_HEX='5037473602000100e80300000000000010010000010000000100000001000000010000000100000000000000000000000000000000000000000000000000000002000000c80000000000000005000000000000001a0007010000000066000000000000000000030aecc101008038010002000000e78e'


def frame(payload):
    body=bytes((len(payload),0x61,0xF0))+payload
    return b"\xfe"+body+bytes((health._xor(body),))


def sample(*,at=1,result="response",session="owner-generation-1",counters=None,tick=100):
    result_dict={"schema":health.SCHEMA,"host_time":at,"session":session,"result":result}
    if result=="response":
        values=dict.fromkeys(health.decoder.HEALTH_COUNTERS,0)
        values.update(counters or {})
        result_dict["diagnostic"]={"version":2,"status":0,"counters":values,
            "sample_tick":tick,"writer_contention_dropped":0,
            "heap":{"total_bytes":115180,"free_bytes":100000,"free_error_count":0}}
    return result_dict


class FramingTests(unittest.TestCase):
    def test_pinned_c_health_reply(self):
        decoded=health.decode_frame(frame(bytes.fromhex(C_HEALTH_HEX)))
        self.assertEqual(decoded["version"],2)
        self.assertEqual(decoded["counters"]["af_no_route"],1)
        self.assertEqual(decoded["counters"]["af_cca_failure"],1)
        self.assertEqual(decoded["counters"]["af_other_failure"],1)
        self.assertEqual(decoded["first_fault"],{"kind":"NV_FAILURE","arg":0x0107,"tick":0,"status":7,"site":1})
        self.assertEqual(decoded["runtime_concentrator"],{"enable":0,"route_cache":0,"discovery_seconds":3,"radius":10})
        self.assertEqual(decoded["heap"],{"total_bytes":115180,"free_bytes":80000,"free_error_count":2,"accounting_consistent":True})

    def test_exact_whole_frame_and_both_integrities(self):
        good=frame(bytes.fromhex(C_HEALTH_HEX))
        for bad in (b"",good[:-1],good+b"\x00",good+good,b"\x00"+good,
                    good[:2]+b"\x41"+good[3:],good[:-1]+bytes((good[-1]^1,))):
            with self.assertRaises(ValueError): health.decode_frame(bad)
        for offset in (0,4,5,6,7,8,12,16,17,18,84,100,105):
            payload=bytearray.fromhex(C_HEALTH_HEX);payload[offset]^=0x80
            with self.assertRaises(ValueError): health.decode_frame(frame(bytes(payload)))

    def test_request_is_read_only_and_version_bounded(self):
        self.assertEqual(health.request_frame(1).hex(),"fe0221f00100d2")
        self.assertEqual(health.request_frame(2).hex(),"fe0221f00200d1")
        with self.assertRaises(ValueError): health.request_frame(3)


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_existing_owner_only_one_exchange(self):
        requests=[]
        async def owner(raw):
            requests.append(raw);return frame(bytes.fromhex(C_HEALTH_HEX))
        client=health.DiagnosticClient(owner,session="opaque-generation")
        result=await client.probe()
        self.assertEqual(requests,[health.request_frame(2)])
        self.assertEqual(result["result"],"response")
        self.assertFalse(result["reboot_identity_known"])
        self.assertGreaterEqual(result["elapsed_ms"],0)

    async def test_timeout_invalidates_late_response_matcher(self):
        cancelled=False
        async def stalled(raw):
            nonlocal cancelled
            try: await asyncio.sleep(10)
            finally: cancelled=True
        client=health.DiagnosticClient(stalled,session="generation")
        result=await client.probe(timeout_seconds=0.001)
        self.assertEqual(result["result"],"timeout")
        self.assertTrue(cancelled)
        with self.assertRaisesRegex(RuntimeError,"SESSION_BOUNDARY"):
            await client.probe()

    async def test_unmatched_reply_is_not_health(self):
        async def owner(raw): return b"\xfe\x00\x61\x01\x60"
        client=health.DiagnosticClient(owner,session="generation")
        self.assertEqual((await client.probe())["result"],"invalid_response")
        self.assertTrue(client.poisoned)

    async def test_no_parallel_probe(self):
        entered=asyncio.Event();release=asyncio.Event()
        async def owner(raw):
            entered.set();await release.wait();return frame(bytes.fromhex(C_HEALTH_HEX))
        client=health.DiagnosticClient(owner,session="generation")
        pending=asyncio.create_task(client.probe());await entered.wait()
        with self.assertRaisesRegex(RuntimeError,"ALREADY_PENDING"): await client.probe()
        release.set();await pending


class AssessmentTests(unittest.TestCase):
    def test_reply_is_not_mesh_health(self):
        result=health.assess([sample()])
        self.assertEqual(result["transport"],"MT_REPLY_RECEIVED")
        self.assertEqual(result["network"],"UNKNOWN")
        self.assertEqual(result["automatic_actions"],[])

    def test_counter_domains_stay_distinct(self):
        observations=[sample(),sample(at=2,tick=101,counters={"af_no_route":2,"af_cca_failure":3,"af_no_ack":4})]
        result=health.assess(observations,same_boot=True)
        self.assertEqual(result["counter_delta"]["af_no_route"],2)
        self.assertEqual(result["counter_delta"]["af_cca_failure"],3)
        self.assertEqual(result["counter_delta"]["af_no_ack"],4)
        self.assertEqual(result["network"],"UNKNOWN")
        self.assertIsNone(health.assess(observations)["counter_delta"])

    def test_reboot_sessions_saturation_and_wrap(self):
        for observations in ([sample(tick=100),sample(at=2,tick=99)],
             [sample(counters={"af_success":3}),sample(at=2,counters={"af_success":2})]):
            self.assertEqual(health.assess(observations,same_boot=True)["delta_status"],"COUNTER_RESET_OR_BOOT_BOUNDARY")
        observations=[sample(tick=0xFFFFFFF0),sample(at=2,tick=0x20,counters={"af_success":1})]
        self.assertEqual(health.assess(observations,same_boot=True)["counter_delta"]["af_success"],1)
        observations[1]["session"]="new-generation"
        self.assertIsNone(health.assess(observations,same_boot=True)["counter_delta"])
        observations=[sample(),sample(at=2,counters={"af_success":0xFFFFFFFF})]
        self.assertEqual(health.assess(observations,same_boot=True)["delta_status"],"SATURATED_COUNTER_DELTA_UNKNOWN")

    def test_silent_network_stall_requires_independent_traffic(self):
        traffic={"attempted":3,"succeeded":0,"timed_out":3,"representative_awake_routers":2,"window_seconds":30,"host_connected":True}
        self.assertEqual(health.assess([sample()],network=traffic)["network"],"POSSIBLE_NETWORK_STALL_REQUIRES_INVESTIGATION")
        for key,value in (("representative_awake_routers",1),("window_seconds",29),("host_connected",False),("timed_out",2)):
            changed={**traffic,key:value}
            self.assertEqual(health.assess([sample()],network=changed)["network"],"UNKNOWN")
        self.assertEqual(health.assess([sample(counters={"nv_failure":1})],network=traffic)["network"],"STOP_TRIAL_NV_FAULT_EVIDENCE")

    def test_timeout_is_not_a_crash_and_recovery_is_bounded(self):
        result=health.assess([sample(result="timeout"),sample(at=2,result="timeout")])
        self.assertIn("TRANSPORT_OR_COORDINATOR",result["transport"])
        self.assertEqual(result["network"],"UNKNOWN")
        self.assertEqual(result["recovery"]["automatic_reset_budget"],0)
        self.assertEqual(result["recovery"]["owner_reconnect_budget_after_evidence_capture"],1)

    def test_memory_samples_are_not_low_water_or_allocation_failures(self):
        first,second=sample(),sample(at=2)
        second["diagnostic"]["heap"]["free_bytes"]=90000
        result=health.assess([first,second])
        self.assertEqual(result["heap"]["minimum_sampled_free_bytes"],90000)
        self.assertEqual(result["heap"]["actual_low_water_or_largest_block"],"UNKNOWN")
        second["diagnostic"]["heap"]["free_error_count"]=1
        self.assertEqual(health.assess([second])["network"],"STOP_TRIAL_ALLOCATOR_FAULT_EVIDENCE")

    def test_malformed_saved_evidence_fails(self):
        for bad in ([],[{}],[sample(at=float("nan"))],[sample(counters={"af_success":-1})],
                    [sample(at=2),sample(at=1)]):
            with self.assertRaises(ValueError):health.assess(bad)


if __name__=="__main__": unittest.main()
