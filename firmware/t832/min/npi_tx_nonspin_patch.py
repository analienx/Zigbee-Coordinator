"""Stop NPI TX ready self-post spin while physical UART completion is pending.

The existing TX_DONE ISR event is the authoritative wakeup for an accepted
write. A *rejected* write instead uses the bounded one-shot retry clock.
"""
from npi_srsp_fairness_patch import replace_in_function

def apply(sdk, replace_exact, changes):
    task="source/ti/zstack/npi/npi_task.c"
    replace_in_function(sdk,"static void NPITask_process(void)\n{",[
        ("                    if (npiTxRetryPending)\n"
         "                    {\n"
         "                        // The one-shot timer will re-enable this event;\n"
         "                        // keep other NPI traffic responsive meanwhile.\n",
         "                    if (npiTxRetryPending || NPITL_checkNpiBusy())\n"
         "                    {\n"
         "                        // Do not repost into a busy-poll loop. A synchronous\n"
         "                        // rejected write is woken by the one-shot timer;\n"
         "                        // an accepted UART write is woken by TX_DONE.\n")
    ], changes)
    return [task]
