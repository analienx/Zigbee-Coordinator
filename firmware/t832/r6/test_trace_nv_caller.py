"""Hosted negative controls for the Q3 production caller trace gate."""
import unittest

import trace_nv_caller as t


def hit(path, match, code=None):
    return {'file': path, 'line': 1, 'match': match,
            'code': match if code is None else code,
            'context': [match]}


class TraceNvCallerTest(unittest.TestCase):
    def good_hits(self):
        return [
            hit('sdk/source/ti/zstack/startup/main.c',
                'zstack_user0Cfg.nvFps.initNV(NULL);'),
            hit('sdk/source/ti/zstack/osal/osal_nv.c',
                'pZStackCfg->nvFps.initNV( NULL );'),
        ]

    def test_both_required_callers_pass(self):
        prod, calls, required = t.analyze_hits(self.good_hits())
        self.assertEqual(len(prod), 2)
        self.assertEqual(len(calls), 2)
        self.assertEqual(set(required), {'znp_startup', 'osal_nv'})

    def test_production_mentions_but_zero_calls_fail(self):
        hits = [hit('sdk/source/ti/zstack/startup/main.c',
                    'if (zstack_user0Cfg.nvFps.initNV)')]
        with self.assertRaisesRegex(ValueError, 'zero actual initNV calls'):
            t.analyze_hits(hits)

    def test_each_required_caller_is_mandatory(self):
        good = self.good_hits()
        for keep in (good[:1], good[1:]):
            with self.subTest(keep=keep[0]['file']):
                with self.assertRaisesRegex(ValueError, 'required ignored-return caller'):
                    t.analyze_hits(keep)

    def test_generic_extra_call_does_not_replace_required_callers(self):
        hits = [hit('sdk/foo.c', 'thing.initNV(NULL);')] + self.good_hits()[:1]
        with self.assertRaisesRegex(ValueError, 'required ignored-return caller'):
            t.analyze_hits(hits)

    def test_required_call_must_be_standalone_ignored_return(self):
        path = 'sdk/source/ti/zstack/startup/main.c'
        bad_code = (
            'if (zstack_user0Cfg.nvFps.initNV(NULL)) {',
            'return zstack_user0Cfg.nvFps.initNV(NULL);',
        )
        for code in bad_code:
            with self.subTest(code=code):
                hits = [hit(path, code)] + self.good_hits()[1:]
                with self.assertRaisesRegex(ValueError, 'required ignored-return caller'):
                    t.analyze_hits(hits)

    def observed_hit(self):
        match = 't832r11InitStatus=zstack_user0Cfg.nvFps.initNV(NULL);'
        h = hit('sdk/source/ti/zstack/startup/main.c', match)
        h['context'] = [
            'uint8_t t832r11InitStatus;',
            'T832R11_enter(T832R11_SITE_MAIN_INIT);',
            match,
            'T832R11_exit(T832R11_SITE_MAIN_INIT,(uint16_t)t832r11InitStatus,T832R11_STATE_UNKNOWN,T832R11_STATE_UNKNOWN,T832R11_VALID_STATUS);',
        ]
        return h

    def test_observed_assignment_without_report_fails(self):
        hits = [hit('sdk/source/ti/zstack/startup/main.c',
                    'status = zstack_user0Cfg.nvFps.initNV(NULL);')] + self.good_hits()[1:]
        with self.assertRaisesRegex(ValueError, 'lacks observer report'):
            t.analyze_hits(hits)

    def test_observed_assignment_with_report_passes(self):
        hits = [self.observed_hit()] + self.good_hits()[1:]
        prod, calls, required = t.analyze_hits(hits)
        self.assertEqual(set(required), {'znp_startup', 'osal_nv'})

    def test_observed_status_escape_fails(self):
        h = self.observed_hit()
        h['context'] = h['context'] + ['if (t832r11InitStatus) {']
        with self.assertRaisesRegex(ValueError, 'escapes'):
            t.analyze_hits([h] + self.good_hits()[1:])

    def test_comments_and_strings_are_not_executable_calls(self):
        lines = [
            '/*',
            'zstack_user0Cfg.nvFps.initNV(NULL);',
            '*/',
            '// zstack_user0Cfg.nvFps.initNV(NULL);',
            '"zstack_user0Cfg.nvFps.initNV(NULL);"',
            'zstack_user0Cfg.nvFps.initNV(NULL);',
        ]
        code = t.executable_code_lines(lines)
        self.assertEqual([line.strip() for line in code[:-1]], ['', '', '', '', ''])
        self.assertEqual(code[-1].strip(), 'zstack_user0Cfg.nvFps.initNV(NULL);')


if __name__ == '__main__':
    unittest.main()
