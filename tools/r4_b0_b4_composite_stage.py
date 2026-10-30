#!/usr/bin/env python3
"""Exact-pinned B2 application seam + canonical B4 F0/F2 on B1/B3 fusion.

Only a disposable /tmp TI SDK that has ALREADY passed the strict B1+B3
source fusion. Reconciles B4's original unmodified-TI file preimage check to
*the verified B1-owned source fingerprints*, NEVER to arbitrary modified files.
No radio, flash, NV writes, or new UART owner. B2 MTO policy remains disabled
unless a real persisted setting enables it; this does not enable MTO by default.
"""
import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

TI_SHA="3615ad5d3f4f271258d18a2f5ce1785064ff9a58"
B2_SHA="d13a48f5226d42e247a17d9198d84c94a4415030"
B2_FAILURE_SHA="530a52631fbde274a2ae356c490bad71b47168a6"
B4_SHA="3231abb1f13210eb88afe13ff7b7f9f29709cd6b"
ZDO="source/ti/zstack/stack/zdo/zd_app.c"
NVO="source/ti/common/nv/nvocmp.c"
SYS="source/ti/zstack/mt/mt_sys.c"
TASK="source/ti/zstack/npi/npi_task.c"
UART="source/ti/zstack/npi/npi_tl_uart.c"
TL="source/ti/zstack/npi/npi_tl.c"
CLIENT="source/ti/zstack/npi/npi_client_mt.c"
MT="source/ti/zstack/mt/mt.c"
MTZDO="source/ti/zstack/mt/mt_zdo.c"
STACK="source/ti/zstack/startup/zstackstartup.c"
COMPOSITE_WRITES=(ZDO,NVO,TASK,UART,SYS,TL,CLIENT,MT,STACK,MTZDO)

def outside_write_scope(sdk):
    """Fingerprint all preexisting SDK changes outside this stage's allowlist."""
    excluded=[":(exclude)"+name for name in COMPOSITE_WRITES]
    diff=subprocess.check_output(["git","-C",str(sdk),"diff","--binary",
                                  "--no-ext-diff","HEAD","--",".",*excluded])
    untracked=subprocess.check_output(["git","-C",str(sdk),"ls-files","--others",
                                      "--exclude-standard","-z"])
    files={}
    for raw in untracked.split(b"\0"):
        if not raw:continue
        name=raw.decode("utf-8")
        if name in COMPOSITE_WRITES:continue
        path=sdk/name
        if path.is_symlink() or not path.is_file():
            raise ValueError("COMPOSITE_UNTRUSTED_UNTRACKED_"+name)
        files[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    return {"tracked_delta_sha256":hashlib.sha256(diff).hexdigest(),
            "untracked_sha256":files}

def load(name,path):
    if path.is_symlink() or not path.is_file(): raise ValueError("UNTRUSTED_PINNED_SCRIPT "+name)
    if str(path.parent) not in sys.path:sys.path.insert(0,str(path.parent))
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def replace_once(text, old, new, label):
    if text.count(old)!=1:raise ValueError("COMPOSITE_DRIFT "+label+" occurrences="+str(text.count(old)))
    return text.replace(old,new,1)

def extract(text,signature):
    anchor=signature+"\n{"
    if text.count(anchor)!=1:raise ValueError("COMPOSITE_CALLBACK_AMBIGUOUS "+signature)
    start=text.index(anchor); pos=start+len(signature)+1;depth=0
    for idx in range(pos,len(text)):
        if text[idx]=="{":depth+=1
        elif text[idx]=="}":
            depth-=1
            if depth==0:return text[start:idx+1]
    raise ValueError("UNBALANCED_C_SOURCE "+signature)

def run(sdk,baseline,b1receipt,fusionreceipt,b2script,b2failurescript,b4v3script,b4v4script,b2sha,b2failuresha,b4sha):
    sdk=sdk.resolve()
    if not str(sdk).startswith("/tmp/") or not (sdk/".git").exists():
        raise ValueError("ONLY_HOSTED_DISPOSABLE_TI_SOURCE")
    if subprocess.check_output(["git","-C",str(sdk),"rev-parse","HEAD"],text=True).strip()!=TI_SHA:
        raise ValueError("SDK_SHA_DRIFT")
    if b2sha!=B2_SHA or b2failuresha!=B2_FAILURE_SHA or b4sha!=B4_SHA:
        raise ValueError("SIBLING_COMMIT_PIN_DRIFT")
    preserved_scope=outside_write_scope(sdk)
    prior=json.loads(fusionreceipt.read_text())
    b1=json.loads(b1receipt.read_text())
    if (prior.get("schema")!="r4-b1-b3-partial-security-fusion-v1" or
        prior.get("source_ready") is not False or
        b1.get("post_b1_security_fusion")!="B1_PLUS_SELECTED_B3_IMMUTABLE_INPUTS"):
        raise ValueError("B1_B3_FUSION_INCOMPLETE")
    b2=load("r4_immutable_b2",b2script)
    if (getattr(b2,"SDK_SHA",None)!=TI_SHA or
        "source_is_candidate_only" not in b2script.read_text()):
        raise ValueError("B2_MTO_ACTUAL_DONOR_SCRIPT_DRIFT")
    b2failure=load("r4_immutable_b2_failure_guard",b2failurescript)
    if (getattr(b2failure,"SDK_SHA",None)!=TI_SHA or
        getattr(b2failure,"ZDAPP",None)!=ZDO or
        getattr(b2failure,"ZDAPP_BLOB",None)!="d67a7798a3e6a8681faddebf5e4b87b4b4c60421" or
        getattr(b2failure,"FAILURE_SIGNATURE",None)!="void ZDO_ManytoOneFailureIndicationCB()" or
        "RTG_MTORouteReq();" not in b2failure.FAILURE_AFTER or
        "zgConcentratorEnable != TRUE" not in b2failure.FAILURE_AFTER or
        "devState != DEV_ZB_COORD && devState != DEV_ROUTER" not in b2failure.FAILURE_AFTER):
        raise ValueError("B2_FAILURE_GUARD_PINNED_SOURCE_DRIFT")
    current=(sdk/ZDO).read_text()
    if hashlib.sha256(current.encode()).hexdigest()!=b1.get("modified_zdapp_sha256"):
        raise ValueError("B1_B3_ZDO_PREIMAGE_HASH_DRIFT")
    old=extract(current,"void ZDApp_ForceConcentratorChange( void )")
    if old!=b2.ORIGINAL:
        raise ValueError("B2_MTO_CALLBACK_BASELINE_DRIFT")
    new=b2.FIXED
    # Safe on missing optional MTO NV settings: halt MTO rearming, but DO NOT
    # assert security HOLD merely because optional MTO config is not present.
    # OSAL/NVS hard I/O failures still flow through the B1 NVOCMP latch.
    if ("if (!enable_ok || !discovery_ok || enable > 1u)" not in new or
        "OsalPortTimers_stopTimer" not in new):
        raise ValueError("B2_FAIL_CLOSED_MTO_GUARDS_MISSING")
    patched=replace_once(current,old,new,"B2_MTO_FUSED_APP")
    # Keep TI's binary RTG engine and 1000ms limiter intact. Only reject
    # stale MTO failure callbacks while MTO is inactive or the node unformed.
    old_failure=extract(patched,b2failure.FAILURE_SIGNATURE)
    if old_failure!=b2failure.FAILURE_BEFORE:
        raise ValueError("B2_MTO_FAILURE_CALLBACK_PREIMAGE_DRIFT")
    patched=replace_once(patched,b2failure.FAILURE_BEFORE,
                         b2failure.FAILURE_AFTER,"B2_MTO_FAILURE_GUARD")
    (sdk/ZDO).write_text(patched,encoding="utf-8",newline="")

    # B4 v3 expects pristine TI NPI_TASK/UART/MT_SYS. These THREE
    # files are legitimately B1-modified (the MT restore-read gate and
    # Z-Stack identity live in MT_SYS). Permit only the exact B1 receipt
    # fingerprints; all other B4 donor files remain pinned to pristine TI.
    bindings=b1.get("additional_source_bindings",{})
    expected={}
    for name in (TASK,UART,SYS):
        keys=[key for key,val in bindings.items() if val==name]
        if len(keys)!=1:raise ValueError("B1_NPI_SOURCE_RECEIPT_AMBIGUOUS "+name)
        v=b1.get(keys[0])
        if not isinstance(v,str) or len(v)!=64:
            raise ValueError("B1_NPI_DIGEST_MISSING "+name)
        if hashlib.sha256((sdk/name).read_bytes()).hexdigest()!=v:
            raise ValueError("B1_NPI_SOURCE_PREIMAGE_HASH_DRIFT "+name)
        expected[name]=v
    v3source=b4v3script.read_text()
    old_check='''        if actual != pristine:
            raise ValueError("source modified before B4 overlay: " + path)'''
    new_check='''        if path in B1_NPI_PRIOR_HASHES:
            if hashlib.sha256(actual).hexdigest() != B1_NPI_PRIOR_HASHES[path]:
                raise ValueError("B1 source changed before B4 overlay: " + path)
        elif actual != pristine:
            raise ValueError("source modified before B4 overlay: " + path)'''
    v3source=replace_once(v3source,old_check,new_check,"B4_B1_VERIFIED_PREIMAGE_RULE")
    # B1 and B4 intentionally use the SAME physical UART2 handle and EOT
    # event. The immutable standalone B4 script rejects all previous owners.
    # Here the B1 receipt sealed the exact already-owned preimage; allow only
    # that owner and chain its callback AFTER B4 leaves its critical section.
    b4_subscription_guard = (
        '    if "params.eventCallback" in uart or "params.eventMask" in uart:\n'
        '        raise ValueError("existing UART event subscriber: do not replace ownership")'
    )
    reconciled_guard = (
        '    if (uart.count("params.eventCallback = b1_startup_uart_event;") != 1 or\n'
        '            uart.count("params.eventMask |= UART2_EVENT_TX_FINISHED;") != 1 or\n'
        '            uart.count("static void b1_startup_uart_event(UART2_Handle handle,") != 1 or\n'
        '            uart.count("if (event & UART2_EVENT_TX_FINISHED) b1_startup_tx_eot();") != 1):\n'
        '        raise ValueError("unknown UART event owner: retain fail-closed policy")'
    )
    v3source=replace_once(v3source,b4_subscription_guard,reconciled_guard,
                          "B1_EXACT_UART_CALLBACK_OWNERSHIP")
    b4_callback_tail = (
        '        OsalPort_leaveCS(key);\n'
        '    }\n'
        '}\n\n'
        '""" + callback_anchor, 1)'
    )
    chained_callback_tail = (
        '        OsalPort_leaveCS(key);\n'
        '        /* B1 startup is notified only AFTER B4 releases the UART CS. */\n'
        '        b1_startup_uart_event(handle, event, data, userArg);\n'
        '    }\n'
        '}\n\n'
        '""" + callback_anchor, 1)'
    )
    v3source=replace_once(v3source,b4_callback_tail,chained_callback_tail,
                          "B4_TO_B1_SINGLE_UART_EOT_FANOUT")
    v3source="B1_NPI_PRIOR_HASHES = "+repr(expected)+"\n"+v3source
    v3local=baseline/"b4_v3_exact_b1_reconciled.py"
    v3local.write_text(v3source,encoding="utf-8")
    v3=load("r4_reviewed_b4_v3_reconciled",v3local)
    native_v3=v3.apply(sdk)
    # B1 subscribed before B4's overlay. B4 is now the ONLY selected physical
    # subscriber and forwards to B1 *after* its short counter critical section.
    # The generated source used to select B4 and then overwrite that pointer
    # with B1 just before UART2_open (while misleading static counts passed).
    uart_path=sdk/UART
    combined_uart=uart_path.read_text(encoding="utf-8")
    prior_owner="    params.eventCallback = b1_startup_uart_event;\n"
    if combined_uart.count(prior_owner)!=1:
        raise ValueError("B1_B4_OLD_UART_SUBSCRIBER_PREIMAGE_DRIFT")
    combined_uart=combined_uart.replace(prior_owner,"",1)
    # The actual initializer and callback bodies are source-compiled and the
    # event callback *passed to UART2_open* is executed with an intercepted
    # UART2_open; negative mutants cover override, missing and duplicate B1.
    from r4_uart_event_selection import exercise as exercise_uart_selection
    receipt=exercise_uart_selection(combined_uart)
    uart_path.write_text(combined_uart,encoding="utf-8",newline="")
    if receipt["status"]!="PASS_SELECTED_UART2_OPEN_CALLBACK_COMPILED_AND_MUTANTS_REJECTED":
        raise ValueError("B1_B4_SELECTED_UART_EVENT_BEHAVIORAL_HOLD")
    v4=load("r4_immutable_b4_v4",b4v4script)
    native_v4=v4.apply(sdk)
    # Fix the pinned TI outbound MT response handoff on the EXACT composed
    # source; leave native ZNP frame structure, serial and routing untouched.
    from r4_af_register_handoff import apply as fix_af_register_handoff
    af_handoff = fix_af_register_handoff(sdk)
    from r4_af_register_handoff_harness import exercise as exercise_af_handoff
    af_behavior=exercise_af_handoff(sdk)
    if af_behavior["status"] != "AF_ACTUAL_TI_C_OUTBOUND_FAILURE_PATH_AND_MUTANTS_PASS":
        raise ValueError("AF_REAL_OUTBOUND_BEHAVIOR_UNPROVEN")
    # v4.2 F2 causal patch composes on the actual 4cfe AF-fix source only.
    from r4_f2_v42_causal import apply as extend_f2_causality
    f2_causal = extend_f2_causality(sdk)
    for name in ("source/ti/zstack/npi/npi_client_mt.c", TASK, SYS):
        if f2_causal["before_sha256"][name] != af_handoff["source_modified_sha256"][name]:
            raise ValueError("F2_V42_AFTER_AF_HANDOFF_PREIMAGE_DRIFT_"+name)


    # Correct TI's conditional TX-active latch with the ACTUAL composed UART.
    # An unstarted write must not leave the NPI task blocked forever.
    from r4_uart_tx_liveness import (apply as patch_uart_tx_liveness,
                                     verify_ti_uart2_callback_ownership)
    ti_callback_source = verify_ti_uart2_callback_ownership(sdk)
    tx_liveness = patch_uart_tx_liveness(sdk)
    mt_keys=[key for key,path in bindings.items() if path==MT]
    if (len(mt_keys)!=1 or hashlib.sha256((sdk/MT).read_bytes()).hexdigest()!=b1.get(mt_keys[0])):
        raise ValueError("F2_V43_MT_B1_PREIMAGE_NOT_BOUND")
    from r4_f2_v43_progress import apply as add_f2_progress
    f2_progress = add_f2_progress(sdk)
    for name in (TL,UART):
        if f2_progress["before_sha256"][name] != tx_liveness["modified_sha256"][name]:
            raise ValueError("F2_V43_TX_SOURCE_CHAIN_DRIFT_"+name)
    from r4_uart_tx_liveness_harness import exercise as exercise_tx_liveness
    tx_c = exercise_tx_liveness(sdk)
    if tx_c["status"] != "PASS_ACTUAL_TI_COMPOSED_C_INTEGRATED_AND_FIVE_MUTANTS":
        raise ValueError("R4_UART_TX_FAILURE_UNWIND_NOT_SOURCE_PROVEN")
    from r4_f2_v43_harness import exercise as exercise_f2_progress
    f2_progress_c=exercise_f2_progress(sdk)
    if f2_progress_c["status"] != "PASS_ACTUAL_F2_V43_240_BYTE_PROGRESS_AND_FROZEN_FIRST_FAULT":
        raise ValueError("R4_F2_V43_ACTUAL_C_FAILED")
    for name in (TL, UART):
        if hashlib.sha256((sdk/name).read_bytes()).hexdigest() != f2_progress["modified_sha256"][name]:
            raise ValueError("R4_UART_TX_LIVENESS_DIGEST_UNBOUND_" + name)

    # v4.4 is a distinct, narrowly scoped successor. Execute the historical
    # v4.3 controls above before patching; qualify final scheduler bodies below.
    from r4_srsp_service import apply as add_srsp_service
    srsp_service = add_srsp_service(sdk)
    for name in (TASK, SYS):
        if srsp_service["before_sha256"][name] != f2_progress["modified_sha256"][name]:
            raise ValueError("V44_SOURCE_CHAIN_DRIFT_" + name)
    from r4_srsp_service_harness import exercise as exercise_srsp_service
    srsp_service_c = exercise_srsp_service(sdk)

    # v4.5: reserve three complete SRSP frames independent of OSAL heap.
    # Qualify the final actual C producer + ownership path after v4.4.
    from r4_srsp_reserve import apply as add_srsp_reserve
    srsp_reserve = add_srsp_reserve(sdk)
    for name in (TASK,):
        if srsp_reserve["before_sha256"][name] != srsp_service["modified_sha256"][name]:
            raise ValueError("V45_NPI_SOURCE_CHAIN_DRIFT_"+name)
    for name in ("source/ti/zstack/npi/npi_client_mt.c",):
        if srsp_reserve["before_sha256"][name] != f2_causal["modified_sha256"][name]:
            raise ValueError("V45_MT_SOURCE_CHAIN_DRIFT_"+name)
    from r4_srsp_reserve_harness import exercise as exercise_srsp_reserve
    srsp_reserve_c = exercise_srsp_reserve(sdk)
    if srsp_reserve_c["status"] != "PASS":
        raise ValueError("V45_STATIC_SRSP_RESERVE_ACTUAL_C_FAILED")

    # F2 v5 is opt-in LEN=9. The legacy LEN=8/minor4 handler stays untouched.
    from r4_f2_v5_flight import apply as add_v5_flight
    v5_flight=add_v5_flight(sdk)
    for name in (TASK, MT, SYS):
        earlier=(srsp_reserve["modified_sha256"][name] if name==TASK else
                 f2_progress["modified_sha256"][name] if name==MT else
                 srsp_service["modified_sha256"][name])
        if v5_flight["before_sha256"][name] != earlier:
            raise ValueError("F2_V5_SOURCE_CHAIN_DRIFT_"+name)
    from r4_f2_v5_harness import exercise as exercise_v5
    v5_actual_c=exercise_v5(sdk)
    if v5_actual_c["status"] != "PASS":
        raise ValueError("F2_V5_FLIGHT_SOURCE_C_FAILED")

    # Queue preference alone does not schedule a priority4 NPI task while
    # the priority5 stack remains runnable. Preserve init ordering; only
    # already-produced SRSP work temporarily elevates the existing owner.
    from r4_srsp_runtime_priority import apply as add_runtime_priority
    runtime_priority=add_runtime_priority(sdk)
    if runtime_priority["before_sha256"][TASK]!=v5_flight["modified_sha256"][TASK]:
        raise ValueError("V46_RUNTIME_PRIORITY_SOURCE_CHAIN_DRIFT")
    if runtime_priority["before_sha256"][CLIENT]!=srsp_reserve["modified_sha256"][CLIENT]:
        raise ValueError("V46_RUNTIME_PRIORITY_MT_SOURCE_CHAIN_DRIFT")
    from r4_srsp_runtime_priority_harness import exercise as exercise_runtime_priority
    runtime_priority_c=exercise_runtime_priority(sdk)
    if runtime_priority_c["status"]!="PASS":
        raise ValueError("V46_RUNTIME_PRIORITY_ACTUAL_C_FAILED")

    from r4_f2_owned_stage import apply as add_owned_stage
    owned_stage=add_owned_stage(sdk,b1['modified_startup_sha256'])
    for name,expected_hash in ((TASK,runtime_priority['modified_sha256'][TASK]),
            (MT,v5_flight['modified_sha256'][MT]),(SYS,v5_flight['modified_sha256'][SYS]),
            (TL,f2_progress['modified_sha256'][TL])):
        if owned_stage['before_sha256'][name]!=expected_hash:
            raise ValueError('V6_SOURCE_CHAIN_'+name)
    from r4_f2_owned_stage_harness import exercise as exercise_owned_stage
    owned_stage_c=exercise_owned_stage(sdk)
    if owned_stage_c['status']!='PASS':raise ValueError('V6_OWNED_STAGE_ACTUAL_C_FAILED')

    # V47: bounded priority6 service for the existing NPI UART owner ONLY
    # after the actual B1 deferred retained-start event. The B1 EOT barrier
    # remains authoritative. This is a candidate, not a hardware fix claim.
    from r4_startup_ingress_priority import apply as apply_startup_npi
    startup_npi = apply_startup_npi(sdk)
    if startup_npi['before_sha256'][TASK] != owned_stage['modified_sha256'][TASK]:
        raise ValueError('V47_V6_NPI_PREIMAGE_HASH_DRIFT')
    if startup_npi['before_sha256'][MTZDO] != b1.get('modified_mt_zdo_sha256'):
        raise ValueError('V47_B1_GUARDED_STARTUP_PREIMAGE_HASH_DRIFT')
    from r4_startup_ingress_priority_harness import exercise as exercise_startup_npi
    startup_npi_c = exercise_startup_npi(sdk)
    if startup_npi_c['status'] != 'PASS':
        raise ValueError('V47_BOUNDED_STARTUP_INGRESS_BEHAVIORAL_FAILURE')

    # V48: the real V47 hardware kept NPI responsive but a posted
    # ZDO_NETWORK_INIT remained pending while Stack dispatched >4k earlier
    # services. Select the existing guarded ZDApp INIT/START task once when
    # its event is already pending; do not post or forge another event.
    from r4_retained_zdapp_fairness import apply as apply_zdapp_fairness
    zdapp_fairness=apply_zdapp_fairness(sdk)
    if zdapp_fairness['source_before_sha256'] != owned_stage['modified_sha256'][STACK]:
        raise ValueError('V48_V47_STACK_PREIMAGE_HASH_DRIFT')

    # The conditional HOLD admission was source/C tested in B1 #122.
    # Enable only after verifying the EXACT canonical B4 F2 linked handler
    # and F1/F0/F2 separate SYS cases in the same disposable SDK.
    sys=(sdk/SYS).read_text(encoding="utf-8")
    if ("case 0xF0:" not in sys or "case 0xF2:" not in sys or
        'MT_BuildAndSendZToolResponse(MT_SRSP_SYS, 0xF2' not in sys or
        "B4_V4_NONCE_AND_BOOT_EPOCH_CANDIDATE" not in sys):
        raise ValueError("B4_F0_F2_DISPATCH_NOT_PRESENT")
    nv=(sdk/NVO).read_text()
    if "b1_management.c" not in nv or "b1_admission.c" not in nv:
        raise ValueError("B1_RF_HOLD_TU_ABSENT")
    nv=replace_once(nv,
        "#define B1_MANAGEMENT_ENABLED 1\n",
        "#define B1_MANAGEMENT_ENABLED 1\n"
        "#define B1_B4_F2_HOLD_DIAGNOSTIC_REVIEWED 1\n",
        "B1_REVIEWED_F2_ADMISSION_ENABLE")
    (sdk/NVO).write_text(nv,encoding="utf-8",newline="")

    # Re-bind ALL mutated B1-source inputs, but only when their current
    # preimages are consistent with the source-fusion receipt. Standalone
    # B1 native sealer's exact-Git-SHA invariants remain mandatory.
    beforehash={}
    afterhash={}
    for name in (ZDO,NVO,TASK,UART,SYS,TL,MT,STACK,MTZDO):
        earlier= b1.get("modified_zdapp_sha256") if name==ZDO else (
            b1.get("modified_nv_sha256") if name==NVO else (
            expected.get(name)))
        if earlier is not None:beforehash[name]=earlier
        afterhash[name]=hashlib.sha256((sdk/name).read_bytes()).hexdigest()
    # Include modified TI npi_client_mt.c in exact-source attestation.
    # Never change the qualified native B1 management C security seal.
    af_client="source/ti/zstack/npi/npi_client_mt.c"
    afterhash[af_client]=hashlib.sha256((sdk/af_client).read_bytes()).hexdigest()
    beforehash[STACK]=owned_stage['before_sha256'][STACK]
    for name in (af_client,):
        if afterhash[name] != runtime_priority["modified_sha256"][name]:
            raise ValueError("F2_V45_RESERVED_CLIENT_RECEIPT_UNBOUND_"+name)
        beforehash[name]=af_handoff["source_before_sha256"][name]
    for name in (TASK,SYS):
        final_expected = (startup_npi['modified_sha256'][TASK] if name == TASK
                          else owned_stage['modified_sha256'][SYS])
    if afterhash[STACK] != zdapp_fairness['source_modified_sha256']:
        raise ValueError('V48_ZDAPP_FINAL_SOURCE_NOT_BOUND')
        if (f2_progress["before_sha256"][name] != f2_causal["modified_sha256"][name] or
                afterhash[name] != final_expected):
            raise ValueError("F2_V42_V47_SOURCE_RECEIPT_UNBOUND_"+name)
    b1["modified_zdapp_sha256"]=afterhash[ZDO]
    b1["modified_nv_sha256"]=afterhash[NVO]
    # The B1-owned guarded MT ZDO TU is modified only by this exact V47
    # successor, whose preimage is sealed above; update the post-link B1
    # receipt rather than weakening its live source-fingerprint check.
    if b1.get("modified_mt_zdo_sha256") != startup_npi['before_sha256'][MTZDO]:
        raise ValueError("V47_MT_ZDO_B1_PREIMAGE_RECEIPT_UNBOUND")
    b1["modified_mt_zdo_sha256"]=afterhash[MTZDO]
    for name in (TASK,UART,SYS,MT,STACK):
        key=[k for k,v in bindings.items() if v==name][0]
        b1[key]=afterhash[name]
    # These new inputs must be checked again by the post-link B1 native sealer,
    # not merely recorded in the source-stage receipt.
    for key,name,value in (
            ("modified_npi_tl_liveness_sha256",TL,afterhash[TL]),
            ("modified_zstack_dispatch_stage_sha256",STACK,afterhash[STACK]),
            ("v6_clock_header_sha256","kernel/tirtos7/packages/ti/sysbios/knl/Clock.h",
             owned_stage['provider_sha256']['kernel/tirtos7/packages/ti/sysbios/knl/Clock.h']),
            ("v6_clock_source_sha256","kernel/tirtos7/packages/ti/sysbios/knl/Clock.c",
             owned_stage['provider_sha256']['kernel/tirtos7/packages/ti/sysbios/knl/Clock.c']),
            ("ti_uart2_driver_sha256","source/ti/drivers/uart2/UART2CC26X2.c",
             ti_callback_source["uart2_driver_sha256"]),
            ("ti_uart2_generic_sha256","source/ti/drivers/UART2.c",
             ti_callback_source["uart2_generic_sha256"])):
        bindings[key]=name
        b1[key]=value
    b1["additional_source_bindings"]=bindings
    required=b1.setdefault("additional_required_functions",[])
    if "NPITL_abortFailedTx" not in required:required.append("NPITL_abortFailedTx")
    for function in ("B4_V43_Request","B4_V43_Snapshot"):
        if function not in required:required.append(function)
    if "B4_V44_Snapshot" not in required: required.append("B4_V44_Snapshot")
    for function in ("B4_V45_SendReservedSrsp", "B4_V45_QueueDynamicSrsp", "B4_V45_ReleaseReserved",
                     "B4_V5_Record", "B4_V5_NpiPulse", "B4_V5_ReadPage1", "B4_V5_ReadPage2",
                     "B4_SysReadOnlyDiagnosticsV5"):
        if function not in required: required.append(function)
    if "B4_V46_RefreshNpiPriority" not in required:
        required.append("B4_V46_RefreshNpiPriority")
    if "B4_V47_ArmStartupNpi" not in required:
        required.append("B4_V47_ArmStartupNpi")
    for function in ('B4_V6_MtBegin','B4_V6_MtClaim','B4_V6_MtEnd','B4_V6_StackPulse','B4_V6_UartPulse',
                     'B4_V6_Checkpoint','B4_V6_Read','B4_SysReadOnlyDiagnosticsV6'):
        if function not in required:required.append(function)
    b1["post_b1_b3_b2_b4_source_composition"]="EXPLICIT_SEMANTIC_FUSION_STANDALONE_NATIVE_PENDING"
    b1["b2_pinned_commit"]=B2_SHA
    b1["b2_mto_failure_guard_pinned_commit"]=B2_FAILURE_SHA
    b1["b4_pinned_commit"]=B4_SHA
    if outside_write_scope(sdk)!=preserved_scope:
        raise ValueError("COMPOSITE_CHANGED_SDK_OUTSIDE_REVIEWED_WRITE_SCOPE")
    b1receipt.write_text(json.dumps(b1,indent=2,sort_keys=True)+"\n")
    return {
        "schema":"r4-b0-b4-source-composite-v1",
        "b0_ti_sdk_sha":TI_SHA,
        "prior_fusion_b3_sha":prior["b3_input_sha"],
        "b2_source_sha":B2_SHA,"b4_source_sha":B4_SHA,
        "b2_mto_failure_guard_source_sha":B2_FAILURE_SHA,
        "b2_mto_nv_reads_failclosed":True,
        "b2_mto_failure_guard":"ONLY_ACTIVE_FORMED_CONCENTRATOR",
        "b2_added_retry_throttle":False,
        "b2_p1_capacities":"REQUIRES_SEPARATE_CC_OPTS_STAGE",
        "b4_v3_patch_evidence":native_v3,
        "b4_v4_patch_evidence":native_v4,
        "af_register_outbound_handoff":af_handoff,
        "af_register_actual_c_behavior":af_behavior,
        "f2_v42_causal_response_path":f2_causal,
        "f2_v43_request_uart_progress":f2_progress,
        "f2_v43_actual_c":f2_progress_c,
        "srsp_service_v44":srsp_service,
        "srsp_service_v44_actual_c":srsp_service_c,
        "srsp_reserve_v45":srsp_reserve,
        "srsp_reserve_v45_actual_c":srsp_reserve_c,
        "f2_v5_flight":v5_flight,
        "f2_v5_actual_c":v5_actual_c,
        "srsp_runtime_priority":runtime_priority,
        "srsp_runtime_priority_actual_c":runtime_priority_c,
        "owned_overdue_stage":owned_stage,
        "owned_overdue_stage_actual_c":owned_stage_c,
        "v47_bounded_startup_ingress":startup_npi,
        "v47_startup_ingress_actual_c":startup_npi_c,
        "v48_retained_zdapp_fairness":zdapp_fairness,
        "uart_tx_liveness_fix":tx_liveness,
        "uart_tx_liveness_actual_c":tx_c,
        "ti_uart2_callback_ownership":ti_callback_source,
        "composite_write_scope":{"allowed_paths":list(COMPOSITE_WRITES),
                                 "outside_scope_unchanged":True,
                                 "preserved_fingerprint":preserved_scope},
        "b1_f1_and_b4_f0_f2_dispatch":True,
        "b1_b4_uart_single_owner_tx_finished_fanout":True,
        "b1_f2_hold_exception_enabled_for_disposable_composite":True,
        "source_modified_sha256":afterhash,
        "b1_prior_source_sha256":beforehash,
        "actual_native_binary":"REQUIRES_COMPILATION",
        "B3_NVOCMP_compaction_full_semantic_fusion":False,
        "B3_seed_derived_status_abi_fusion":False,
        "B2_closed_rtg_validated":False,
        "physical_hardware_validated":False,
        "source_ready":False,"flash_authorized":False,
    }

def main():
    p=argparse.ArgumentParser()
    for name in ("sdk","baseline","b1-receipt","fusion-receipt","b2-script","b2-failure-script","b4-v3-script","b4-v4-script","receipt"):
        p.add_argument("--"+name,required=True,type=Path)
    p.add_argument("--b2-sha",required=True)
    p.add_argument("--b2-failure-sha",required=True)
    p.add_argument("--b4-sha",required=True)
    a=p.parse_args()
    a.baseline.mkdir(parents=True,exist_ok=True)
    result=run(a.sdk,a.baseline,a.b1_receipt,a.fusion_receipt,a.b2_script,
               a.b2_failure_script,a.b4_v3_script,a.b4_v4_script,
               a.b2_sha,a.b2_failure_sha,a.b4_sha)
    a.receipt.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"status":"COMPOSED_SOURCE_NEEDS_NATIVE_AND_PHYSICAL_PROOF",
                      "source_ready":False,"flash_authorized":False},sort_keys=True))

if __name__=="__main__":
    main()
