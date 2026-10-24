import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from stage_card_trial import replace_verified


def sha(data):
    return hashlib.sha256(data).hexdigest()


class CardStagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.card = self.root/"card"
        self.card.mkdir()
        (self.card/"FIRMWARE.BIN").write_bytes(b"old update")
        (self.card/"photo.jpg").write_bytes(b"untouched photograph")
        self.allow = patch("stage_card_trial.BASELINE", sha(b"old update"))
        self.allow.start()

    def tearDown(self):
        self.allow.stop()
        self.temporary.cleanup()

    def test_backup_and_readback_preserve_unrelated_files(self):
        result = replace_verified(self.card, b"new update", sha(b"new update"), self.root/"backup")
        self.assertTrue(result["card_exact_readback_verified"])
        self.assertEqual((self.root/"backup/previous-firmware.bin").read_bytes(), b"old update")
        self.assertEqual((self.card/"FIRMWARE.BIN").read_bytes(), b"new update")
        self.assertEqual((self.card/"photo.jpg").read_bytes(), b"untouched photograph")
        self.assertFalse((self.card/"S3300LAB.TMP").exists())

    def test_unknown_old_file_is_never_overwritten(self):
        (self.card/"FIRMWARE.BIN").write_bytes(b"unrecognized")
        with self.assertRaisesRegex(ValueError, "not a known"):
            replace_verified(self.card, b"new", sha(b"new"), self.root/"backup")
        self.assertEqual((self.card/"FIRMWARE.BIN").read_bytes(), b"unrecognized")
        self.assertFalse((self.root/"backup").exists())

    def test_existing_temporary_file_is_never_overwritten(self):
        (self.card/"S3300LAB.TMP").write_bytes(b"other process")
        with self.assertRaises(ValueError):
            replace_verified(self.card, b"new", sha(b"new"), self.root/"backup")
        self.assertEqual((self.card/"S3300LAB.TMP").read_bytes(), b"other process")

    def test_card_identity_change_stops_before_target_replacement(self):
        calls = []
        def recheck():
            calls.append(1)
            if len(calls) == 2:
                raise ValueError("Card identity changed")
        with self.assertRaisesRegex(ValueError, "identity changed"):
            replace_verified(self.card, b"new", sha(b"new"), self.root/"backup", recheck)
        self.assertEqual((self.card/"FIRMWARE.BIN").read_bytes(), b"old update")

    def test_concurrent_target_change_is_not_overwritten(self):
        calls = []
        def recheck():
            calls.append(1)
            if len(calls) == 2:
                (self.card/"FIRMWARE.BIN").write_bytes(b"concurrent update")
        with self.assertRaisesRegex(ValueError, "changed during"):
            replace_verified(self.card, b"new", sha(b"new"), self.root/"backup", recheck)
        self.assertEqual((self.card/"FIRMWARE.BIN").read_bytes(), b"concurrent update")


if __name__ == "__main__":
    unittest.main()
