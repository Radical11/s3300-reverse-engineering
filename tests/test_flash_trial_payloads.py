import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from flash_trial_payloads import check_image, load_trial


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checksummed(data):
    output = bytearray(data)
    value = (sum(output[:44])+sum(output[48:])) & 0xffffffff
    struct.pack_into("<I", output, 44, value)
    return bytes(output)


class FlashTrialPayloadTests(unittest.TestCase):
    def setUp(self):
        data = bytearray(0x1000d0)
        struct.pack_into("<I", data, 40, 0x00010100)
        struct.pack_into("<I", data, 48, 0x4b230146)
        self.source = checksummed(data)
        data[-1] = 99
        self.candidate = checksummed(data)
        self.baseline = patch("flash_trial_payloads.BASELINE", sha(self.source))
        self.baseline.start()

    def tearDown(self):
        self.baseline.stop()

    def test_exact_image_with_unchanged_metadata_is_accepted(self):
        self.assertEqual(check_image(self.source, self.candidate, sha(self.candidate)), self.candidate)

    def test_candidate_hash_and_length_must_agree(self):
        with self.assertRaisesRegex(ValueError, "exact reviewed"):
            check_image(self.source, self.candidate[:-1], sha(self.candidate[:-1]))
        with self.assertRaisesRegex(ValueError, "exact reviewed"):
            check_image(self.source, self.candidate, sha(self.source))

    def test_version_and_product_changes_rejected_even_with_updated_checksum(self):
        for offset in (40, 48):
            data = bytearray(self.candidate)
            data[offset] ^= 1
            data = checksummed(data)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "Version/product"):
                check_image(self.source, data, sha(data))

    def test_download_descriptor_changes_are_rejected(self):
        data = bytearray(self.candidate)
        data[0x100000] ^= 1
        data = checksummed(data)
        with self.assertRaisesRegex(ValueError, "descriptor changed"):
            check_image(self.source, data, sha(data))

    def test_checksum_and_source_identity_checked_independently(self):
        data = bytearray(self.candidate)
        data[44] ^= 1
        with self.assertRaisesRegex(ValueError, "checksum"):
            check_image(self.source, data, sha(data))
        with self.assertRaisesRegex(ValueError, "source identity"):
            check_image(b"other source", self.candidate, sha(self.candidate))

    def test_unregistered_trial_has_no_file_access(self):
        with self.assertRaisesRegex(ValueError, "Unknown trial"):
            load_trial("arbitrary image")


if __name__ == "__main__":
    unittest.main()
