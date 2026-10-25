"""Static transfer decoding and read-only atlas query boundaries."""
from pathlib import Path
from contextlib import closing
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from map_firmware_atlas import SOURCE_HASH, classify, owner, query, transfer


class TransferTests(unittest.TestCase):
    def test_jump_uses_pc_plus_four_region_at_boundary(self):
        self.assertEqual(transfer(0x0c000004, 0x8ffffffc), ("call", 0x90000010))
        self.assertEqual(transfer(0x08000004, 0x80000000), ("jump", 0x80000010))

    def test_bal_signed_displacement_and_other_conditional_branches(self):
        self.assertEqual(transfer(0x0411ffff, 0x80001000), ("call", 0x80001000))
        self.assertIsNone(transfer(0x0431ffff, 0x80001000))
        self.assertIsNone(transfer(0x10000000, 0x80001000))

    def test_register_calls_are_unresolved_and_return_is_not_tailcall(self):
        self.assertEqual(transfer(0x0320f809, 0), ("indirect_call", None))
        self.assertEqual(transfer(0x03200008, 0), ("indirect_jump", None))
        self.assertIsNone(transfer(0x03e00008, 0))

    def test_function_ownership_is_half_open_and_gaps_stay_unowned(self):
        functions = [{"start": 16, "end_exclusive": 20}, {"start": 24, "end_exclusive": 32}]
        self.assertEqual(owner(functions, [16, 24], 19), 16)
        for address in (0, 20, 23, 32):
            self.assertIsNone(owner(functions, [16, 24], address))

    def test_classification_can_overlap_and_does_not_name_an_api(self):
        self.assertIn("sensor", classify("ConfigSensorC13.c"))
        self.assertIn("rtos", classify("ThreadX _tx_semaphore_get"))
        self.assertEqual(classify("unrelated printable bytes"), [])


class ReadOnlyQueryTests(unittest.TestCase):
    def test_missing_atlas_is_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.sqlite"
            with self.assertRaises(FileNotFoundError):
                query(path, term="raw")
            self.assertFalse(path.exists())

    def test_literal_search_and_artifact_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "atlas.sqlite"
            with closing(sqlite3.connect(path)) as db:
                db.executescript("CREATE TABLE metadata(key,value); CREATE TABLE strings(address,text);"
                                 "CREATE TABLE symbols(artifact_offset,name,address);")
                db.execute("INSERT INTO metadata VALUES ('source_sha256',?)", (SOURCE_HASH,))
                db.executemany("INSERT INTO strings VALUES (?,?)", [(1, "raw_%"), (2, "rawAA")])
                db.executemany("INSERT INTO symbols VALUES (?,?,?)", [(512, "raw_%", 4096), (8192, "raw_%", 4096)])
                db.commit()
            result = query(path, term="_%")
            self.assertEqual(result["string_candidates"], [{"address": 1, "text": "raw_%"}])
            self.assertEqual(len(result["artifact_scoped_symbols"]), 2)
            self.assertNotEqual(result["artifact_scoped_symbols"][0]["artifact_offset"], result["artifact_scoped_symbols"][1]["artifact_offset"])
            with self.assertRaisesRegex(ValueError, "Unknown subsystem"):
                query(path, subsystem="invented")


if __name__ == "__main__":
    unittest.main()
