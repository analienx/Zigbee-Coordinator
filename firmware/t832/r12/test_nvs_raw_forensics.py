"""Synthetic ONLY NVOCMP header/flash comparison tests; no radio access."""
import hashlib
import unittest
import nvs_raw_forensics as n

BLANK=b"\xff"*n.PAGE
def active(payload=b"SECRET_DO_NOT_LOG"):
    data=bytearray(BLANK)
    data[:4]=bytes((0x7c,0x11,(n.VERSION<<2)|0x03,n.SIGNATURE))
    data[16:16+len(payload)]=payload
    return bytes(data)
def image(first):
    return first+BLANK*(n.COUNT-1)

class OfflineNvsTests(unittest.TestCase):
    def test_blanks(self):
        p=n.page_metadata(BLANK)
        self.assertEqual(p["condition"],"fully_erased")
        self.assertEqual(p["non_ff_bytes"],0)
    def test_valid_active_page(self):
        p=n.page_metadata(active())
        self.assertEqual(p["header"],"valid")
        self.assertEqual(p["state"],"active")
    def test_wrong_signature_or_version(self):
        for index in (2,3):
            x=bytearray(active());x[index]=0
            self.assertEqual(n.page_metadata(bytes(x))["header"],"invalid_or_unformatted")
    def test_wrong_page_size_rejected(self):
        with self.assertRaises(ValueError):n.page_metadata(BLANK[:-1])
        with self.assertRaises(ValueError):n.analyze(BLANK)
    def test_preboot_erasure_detected(self):
        a,b,c=image(active()),image(BLANK),image(BLANK)
        r=n.compare_stages(a,b,c)
        self.assertEqual(r["preboot_newly_blank_pages"],[0])
        self.assertEqual(r["postboot_newly_blank_pages"],[])
        self.assertFalse(r["physical_erase_opcode_proven"])
    def test_first_boot_erasure_detected(self):
        a,b,c=image(active()),image(active()),image(BLANK)
        r=n.compare_stages(a,b,c)
        self.assertEqual(r["preboot_newly_blank_pages"],[])
        self.assertEqual(r["postboot_newly_blank_pages"],[0])
        self.assertTrue(r["application_boot_changed_nvs"])
    def test_stable_bytes(self):
        a=image(active())
        r=n.compare_stages(a,a,a)
        self.assertEqual(r["changed_pages"],[])
    def test_partial_programming_not_called_erase(self):
        x=bytearray(active());x[-1]=0x0f
        r=n.compare_stages(image(active()),image(bytes(x)),image(bytes(x)))
        self.assertEqual(r["preboot_newly_blank_pages"],[])
        self.assertTrue(r["flash_programming_changed_nvs"])
        self.assertFalse(r["physical_erase_opcode_proven"])
    def test_output_never_contains_secret_payload(self):
        before=image(active())
        out=str(n.analyze(before))+str(n.compare_stages(before,before,image(BLANK)))
        self.assertNotIn("SECRET_DO_NOT_LOG",out)
        self.assertIn(hashlib.sha256(before).hexdigest(),out)

if __name__=="__main__":unittest.main()
