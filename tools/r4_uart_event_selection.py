#!/usr/bin/env python3
"""Compile the actual composed UART2 event callback and initializer selection.

Hosted-only; extracts final production C bodies and the statements passed to
UART2_open. Reproduces the override bug with a fault mutant, not a parallel
reimplementation of the selected C callback.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

B4 = "B4_NpiUartTxFinishedCallback"
B1 = "b1_startup_uart_event"
OPEN = "uartHandle = UART2_open(CONFIG_DISPLAY_UART, &params);"
OLD = "    params.eventCallback = b1_startup_uart_event;\n"
GOOD = "    params.eventCallback = B4_NpiUartTxFinishedCallback;\n"
COUNTER = "volatile uint32_t B4_NpiUartTxFinishedEvents = 0;"

def extract_function(src, name):
    matches = list(re.finditer(r"\bstatic\s+void\s+"+re.escape(name)+r"\s*\(",src))
    if len(matches)!=1: raise ValueError("UNIQUE_FINAL_CALLBACK_"+name)
    pos=matches[0].start()
    a=src.find("{",pos); level=0
    if a<0: raise ValueError("CALLBACK_BRACE_"+name)
    for i in range(a,len(src)):
        if src[i]=="{":level+=1
        elif src[i]=="}":
            level-=1
            if level==0:return src[pos:i+1]
    raise ValueError("CALLBACK_UNBALANCED_"+name)

def initializer(src):
    # This is the actual ordered production initializer region, including
    # the eventual UART2_open argument. No fabricated callback selection.
    begin="    params.readCallback = NPITLUART_readCallBack;"
    if src.count(begin)!=1 or src.count(OPEN)!=1:
        raise ValueError("AMBIGUOUS_UART2_INITIALIZER")
    a=src.index(begin);b=src.index(OPEN,a)
    return src[a:b+len(OPEN)]

def check_selection(src):
    init=initializer(src)
    selections=re.findall(r"params\.eventCallback\s*=\s*(\w+)\s*;",init)
    if selections!=[B4] or src.count(COUNTER)!=1 or src.count(OLD)!=0 or src.count(GOOD)!=1:
        raise ValueError("UART2_OPEN_CALLBACK_OVERRIDE_OR_MISSING")
    if init.count("params.eventMask = UART2_EVENT_TX_FINISHED;")!=1:
        raise ValueError("UART2_EVENT_MASK_MISSING")
    if init.count("params.eventMask |= UART2_EVENT_TX_FINISHED;")!=1:
        raise ValueError("UART2_B1_EVENT_MASK_MISSING")
    extract_function(src,B4);extract_function(src,B1)
    return init

def run_compiled(src, name, expected_success=True):
    init=initializer(src)
    b1=extract_function(src,B1)
    b4=extract_function(src,B4)
    c=r'''
#include <stdint.h>
#include <assert.h>
typedef void *UART2_Handle;
#define UART2_EVENT_TX_FINISHED 1u
#define CONFIG_DISPLAY_UART 0
typedef void (*UartEvent)(UART2_Handle,uint32_t,uint32_t,void*);
typedef struct {void (*readCallback)(void);void (*writeCallback)(void);
    uint32_t eventMask; UartEvent eventCallback;} UART2_Params;
static UartEvent installed;
static UART2_Handle uartHandle;
static uint32_t b1_calls,cs_entry,cs_leave;
static uint32_t OsalPort_enterCS(void){ ++cs_entry; return 0u; }
static void OsalPort_leaveCS(uint32_t k){(void)k;++cs_leave;}
static void b1_startup_tx_eot(void){assert(cs_entry==cs_leave);++b1_calls;}
static void NPITLUART_readCallBack(void){}
static void NPITLUART_writeCallBack(void){}
static UART2_Handle UART2_open(int id,const UART2_Params *p){
    assert(id==CONFIG_DISPLAY_UART); assert(p->eventMask&UART2_EVENT_TX_FINISHED);
    installed=p->eventCallback;return (void*)1;
}
'''
    main=r'''
int main(void){
    UART2_Params params={0};
'''
    main+='    (void)&B4_NpiUartTxFinishedCallback; (void)&b1_startup_uart_event;\n'
    main+=init+"\n"
    main+=r'''
    assert(uartHandle==(void*)1);assert(installed!=0);
    installed(uartHandle,0u,0u,0);
    assert(B4_NpiUartTxFinishedEvents==0u && b1_calls==0u);
    installed(uartHandle,UART2_EVENT_TX_FINISHED,0u,0);
    assert(B4_NpiUartTxFinishedEvents==1u && b1_calls==1u);
    installed(uartHandle,UART2_EVENT_TX_FINISHED,0u,0);
    assert(B4_NpiUartTxFinishedEvents==2u && b1_calls==2u);
    B4_NpiUartTxFinishedEvents=UINT32_MAX;
    installed(uartHandle,UART2_EVENT_TX_FINISHED,0u,0);
    assert(B4_NpiUartTxFinishedEvents==UINT32_MAX && b1_calls==3u);
    assert(cs_entry==cs_leave && cs_entry==3u);
    return 0;
}
'''
    full=c+"\n"+COUNTER+"\n"+b1+"\n"+b4+"\n"+main
    compiler=shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:raise RuntimeError("MISSING_HOSTED_C_COMPILER")
    with tempfile.TemporaryDirectory(prefix="p7u-r4-uart-event-") as td:
        path=Path(td)/"selected.c";binary=Path(td)/("selected.exe" if os.name=="nt" else "selected")
        path.write_text(full)
        p=subprocess.run([compiler,"-std=c11","-O0","-Wall","-Wextra","-Werror",
                          str(path),"-o",str(binary)],capture_output=True,text=True)
        if p.returncode: raise ValueError("COMPOSED_CALLBACK_C_COMPILE_"+p.stderr[-1700:])
        p=subprocess.run([str(binary)],capture_output=True,text=True)
        if expected_success and p.returncode!=0:
            raise ValueError("COMPOSED_CALLBACK_SELECTED_RUNTIME_FAILURE_"+name+":"+p.stderr[-1600:])
        if not expected_success and p.returncode==0:
            raise ValueError("COMPOSED_CALLBACK_NEGATIVE_MUTANT_NOT_REJECTED_"+name)
    return True

def exercise(src):
    check_selection(src)
    run_compiled(src,"positive")
    # Mutant 1: original code passes previous string-count static gates
    # but UART2_open receives only B1 and F2 counter stays frozen.
    mutant=src.replace(GOOD,GOOD+OLD,1)
    assert mutant.count(GOOD)==1 and mutant.count("b1_startup_uart_event(handle, event, data, userArg);")==1
    try: check_selection(mutant)
    except ValueError: pass
    else:raise ValueError("CALLBACK_OVERRIDE_STATIC_NEGATIVE_NOT_REJECTED")
    run_compiled(mutant,"override",expected_success=False)
    # Mutants 2/3: selected B4 wrapper loses or duplicates its B1 forwarding.
    call="        b1_startup_uart_event(handle, event, data, userArg);"
    if src.count(call)!=1:raise ValueError("B4_FORWARDING_CALL_DRIFT")
    for name,repl in (("dropped","        (void)handle;"),
                      ("twice",call+"\n"+call)):
        run_compiled(src.replace(call,repl,1),name,expected_success=False)
    return {"status":"PASS_SELECTED_UART2_OPEN_CALLBACK_COMPILED_AND_MUTANTS_REJECTED",
            "positive":1,"negative_mutants":3}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--composed-uart",type=Path,required=True)
    a=parser.parse_args()
    print(exercise(a.composed_uart.read_text(encoding="utf-8")))

if __name__=="__main__":main()
