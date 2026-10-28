"""Bounded F2 fairness through the existing mutex, after a completed transaction."""

METHOD = r"""
    #b4F2Waiting = false;

    /** One opt-in F2 reservation. No UART is touched until the current
     * transaction releases ownership. Expiry removes only this reservation.
     * The caller rechecks OTA, owner and active SRSP gates after acquisition.
     */
    async runF2AtBoundary<T>(fn: () => Promise<T>, waitMs = 1000): Promise<T> {
        if (this.#b4F2Waiting) { throw new Error("B4 DIAG_NOT_SUBMITTED_BUSY"); }
        this.#b4F2Waiting = true;
        let acquired = false;
        try {
            if (this.isIdle()) {
                this.#locked = true;
                acquired = true;
            } else {
                await new Promise<void>((resolve, reject) => {
                    let settled = false;
                    const finish = (error?: Error): void => {
                        if (settled) { return; }
                        settled = true;
                        clearTimeout(timer);
                        if (error) { reject(error); }
                        else { acquired = true; resolve(); }
                    };
                    const waiter = {resume: () => finish(), fail: (error: Error) => finish(error)};
                    const timer = setTimeout(() => {
                        const index = this.#queue.indexOf(waiter);
                        if (index >= 0) { this.#queue.splice(index, 1); }
                        finish(new Error("B4 DIAG_NOT_SUBMITTED_BUSY"));
                    }, Math.max(1, Math.min(1000, waitMs)));
                    this.#queue.unshift(waiter);
                });
            }
            return await fn();
        } finally {
            this.#b4F2Waiting = false;
            if (acquired) {
                const next = this.#queue.shift();
                if (next) { next.resume(); }
                else { this.#locked = false; }
            }
        }
    }

"""


def once(source, before, after):
    if source.count(before) != 1:
        raise ValueError("F2_BOUNDARY_SOURCE_DRIFT_" + before[:75])
    return source.replace(before, after, 1)


def apply(mutex, znp):
    mutex = once(mutex, "    tryRunIfIdle<T>(fn: () => Promise<T>): Promise<T> | undefined {",
                 METHOD + "    tryRunIfIdle<T>(fn: () => Promise<T>): Promise<T> | undefined {")
    znp = once(znp, "    private b4F2ConsecutiveTimeouts = 0;",
               "    private b4F2BoundaryAdmission = false;\n    private b4F2ConsecutiveTimeouts = 0;")
    znp = once(znp, "    public b4CanProbeV4(): boolean {", """    public b4SetF2BoundaryAdmission(enabled: boolean): void {
        this.b4F2BoundaryAdmission = enabled === true;
    }

    public b4CanProbeV4(reserveAtBoundary = false): boolean {""")
    znp = once(znp, "            this.queue.isIdle() && this.b4F2NoBlockingWaiters() &&",
               "            (reserveAtBoundary || (this.queue.isIdle() && this.b4F2NoBlockingWaiters())) &&")
    znp = once(znp, """        const result = b4Optional
            ? this.queue.tryRunIfIdle(operation)
            : this.queue.run(operation);""", """        const result = b4Optional && object.command.name === "r4DiagReadOnlyV4" &&
            this.b4F2BoundaryAdmission
            ? this.queue.runF2AtBoundary(operation)
            : b4Optional ? this.queue.tryRunIfIdle(operation) : this.queue.run(operation);""")
    return mutex, znp
