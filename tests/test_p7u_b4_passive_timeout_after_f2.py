"""Source-only F2 quarantine versus passive timeout proof (no radio owner)."""
import ast
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "host" / "r4-b4"
SOURCE = ast.parse((HOST / 'b4_v4_live_collector_overlay.py').read_text(encoding='utf-8'))
METHOD = next(n.value.value for n in SOURCE.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == 'METHOD' for t in n.targets))


class PassiveEvidenceTests(unittest.TestCase):
    def test_runtime_sink_remains_installed_after_optional_f2_poison(self):
        method = METHOD
        slot = method.split("createHostTimeoutSink((record) => this.#b4Persist(record),", 1)[1]
        gate = slot.split("));", 1)[0]
        self.assertIn("this.#b4Operational", gate)
        self.assertIn("this.#b4WorkerReady", gate)
        self.assertNotIn("this.#b4SamplerDisabled", gate)
        after = method.split("#b4Persist(sample: Record<string, unknown>): void {", 1)[1]
        admission = after.split("const id = ++this.#b4RecordId;", 1)[0]
        self.assertNotIn("this.#b4SamplerDisabled ||", admission)
        self.assertIn("this.#b4PendingIds.size >= 4", admission)
        # F2 still independently stops after a genuinely ambiguous request.
        self.assertIn("if (kind === \"FAILED\" || kind === \"QUARANTINED\")", method)
        self.assertIn("this.#b4SamplerDisabled = true;", method)

    def test_real_node_sink_persists_timeout_after_f2_quarantine(self):
        code = r"""
            const assert=require('node:assert/strict');
            const {createHostTimeoutSink}=require(process.argv[1]);
            let operational=true, ready=true, f2Poisoned=true;
            const seen=[];
            const sink=createHostTimeoutSink(e=>seen.push(e),
                                          ()=>operational && ready);
            const a={kind:'AF_SREQ_TIMEOUT',at_ms:25,dropped:0};
            sink(a);sink(a);
            sink({kind:'ZDO_SREQ_TIMEOUT',at_ms:26,dropped:1});
            assert.equal(seen.length,2);
            assert(seen.every(e=>e.kind==='FAILED'
                && e.reason==='PASSIVE_HOST_SREQ_TIMEOUT'
                && e.submissionState==='NO_DIAGNOSTIC_REQUEST'));
            assert.equal(f2Poisoned,true);
            ready=false;
            sink({kind:'UTIL_SREQ_TIMEOUT',at_ms:27,dropped:0});
            assert.equal(seen.length,2);
            console.log('F2_QUARANTINED_PASSIVE_WORKER_READY_PASS');
        """
        proc = subprocess.run(["node", "-e", code, str(HOST / "p7u_host_timeout_sink.cjs")],
                              capture_output=True, text=True, timeout=8)
        self.assertEqual(proc.returncode, 0, proc.stderr[:1000])
        self.assertIn("F2_QUARANTINED_PASSIVE_WORKER_READY_PASS", proc.stdout)

    def test_passive_persist_failure_never_throws_or_retries(self):
        code = r"""
            const assert=require('node:assert/strict');
            const {createHostTimeoutSink}=require(process.argv[1]);
            let attempts=0;
            const sink=createHostTimeoutSink(()=>{attempts++;throw Error('IPC_FAILED');},
                ()=>true);
            const event={kind:'SYS_SREQ_TIMEOUT',at_ms:27,dropped:0};
            assert.doesNotThrow(()=>sink(event));
            assert.doesNotThrow(()=>sink(event));
            assert.equal(attempts,1);
            console.log('IPC_POISON_NO_PRODUCTION_EXCEPTION_NO_RETRY_PASS');
        """
        proc = subprocess.run(["node", "-e", code, str(HOST / "p7u_host_timeout_sink.cjs")],
                              capture_output=True, text=True, timeout=8)
        self.assertEqual(proc.returncode, 0, proc.stderr[:1000])
        self.assertIn("IPC_POISON_NO_PRODUCTION_EXCEPTION_NO_RETRY_PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
