"""Separate host repair: retain waiter ownership across every request failure."""


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("CONFIRMATION_WAITER_SOURCE_DRIFT_" + old[:100])
    return text.replace(old, new, 1)


def wrap(text, method, body_anchor, args):
    """Preserve synchronous errors and the existing mutex operation unchanged."""
    start = text.index('    public ' + method + '(')
    begin = text.index(body_anchor, start) + len(body_anchor)
    depth = 1
    for end in range(begin, len(text)):
        if text[end] == '{': depth += 1
        elif text[end] == '}':
            depth -= 1
            if depth == 0: break
    else: raise ValueError("CONFIRMATION_WAITER_UNBALANCED_METHOD")
    header = text[start:begin]
    owned = 'b4Owned' + method[0].upper() + method[1:]
    wrapper = header + '''
        // Caller supplied confirmation waiter belongs to this request until
        // SRSP admission succeeds. Remove it on all sync/async failures.
        const cleanup = () => {if (typeof waiterID === "number") this.waitress.remove(waiterID);};
        try {
            return this.OWNED(ARGS).catch((error: unknown) => {
                cleanup(); throw error;
            });
        } catch (error) {
            cleanup(); throw error;
        }
    }

'''.replace('OWNED', owned).replace('ARGS', args)
    implementation = text[start:end+1].replace('public ' + method + '(', 'private ' + owned + '(', 1)
    return text[:start] + wrapper + implementation + text[end+1:]


def apply(znp, waitress):
    # No future frame sweep is needed to reclaim an expired confirmation.
    waitress = once(waitress, '                    waiter.timedout = true;\n                    waiter.reject(error);',
        '                    waiter.timedout = true;\n                    this.waiters.delete(ID);\n                    waiter.reject(error);')
    # A normal synchronous writer failure creates an SRSP waiter but never
    # starts its timer. Diagnostics retain their tagged settlement semantics.
    znp = once(znp, '                        this.waitress.b4Cancel(waiter.ID, "B4 diagnostic writer failed");\n                    }\n                    throw error;',
        '                        this.waitress.b4Cancel(waiter.ID, "B4 diagnostic writer failed");\n'
        '                    } else {\n                        this.waitress.remove(waiter.ID);\n                    }\n                    throw error;')
    znp = once(znp, '            this.unpiWriter.writeFrame(unpiFrame);',
        '            try {\n                this.unpiWriter.writeFrame(unpiFrame);\n'
        '            } catch (error) {\n                this.waitress.remove(waiter.ID);\n                throw error;\n            }')
    znp = wrap(znp, 'request', '): Promise<ZpiObject | undefined> {',
               'subsystem, command, payload, waiterID, timeout, expectedStatuses')
    znp = wrap(znp, 'requestZdo', '): Promise<void> {', 'clusterId, payload, waiterID')
    return znp, waitress
