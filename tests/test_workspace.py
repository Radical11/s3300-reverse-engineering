import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import closing

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
import unpack_workspace
from query_workspace import query


class PartitionTests(unittest.TestCase):
    def fixture(self, output):
        raw = b"complete-byte-fixture"
        parts = []
        for start, end in ((0, 8), (8, len(raw))):
            body = raw[start:end]
            file = f"part-{start}.bin"
            (output/file).write_bytes(body)
            parts.append(dict(offset=start, end_exclusive=end, size=end-start,
                              file=file, sha256=hashlib.sha256(body).hexdigest()))
        manifest = dict(source_sha256=hashlib.sha256(raw).hexdigest(), source_bytes=len(raw), carrier_parts=parts)
        (output/"unpacked.json").write_text(json.dumps(manifest))
        return raw, manifest

    def test_roundtrip_and_modified_part_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            raw, _ = self.fixture(output)
            with patch.object(unpack_workspace, "SOURCE_HASH", hashlib.sha256(raw).hexdigest()):
                self.assertTrue(unpack_workspace.verify_partition(output)["byte_exact_source_reassembly"])
                (output/"part-0.bin").write_bytes(b"modified")
                with self.assertRaisesRegex(ValueError, "changed"):
                    unpack_workspace.verify_partition(output)

    def test_path_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            raw, manifest = self.fixture(output)
            manifest["carrier_parts"][0]["file"] = "../outside.bin"
            (output/"unpacked.json").write_text(json.dumps(manifest))
            with patch.object(unpack_workspace, "SOURCE_HASH", hashlib.sha256(raw).hexdigest()):
                with self.assertRaisesRegex(ValueError, "Unsafe"):
                    unpack_workspace.verify_partition(output)

    def test_gap_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            raw, manifest = self.fixture(output)
            manifest["carrier_parts"][1]["offset"] += 1
            (output/"unpacked.json").write_text(json.dumps(manifest))
            with patch.object(unpack_workspace, "SOURCE_HASH", hashlib.sha256(raw).hexdigest()):
                with self.assertRaisesRegex(ValueError, "Noncontiguous"):
                    unpack_workspace.verify_partition(output)


class WorkspaceQueryTests(unittest.TestCase):
    def test_literal_search_wildcards_are_not_expanded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"index.sqlite"
            with closing(sqlite3.connect(path)) as db:
                db.executescript("CREATE TABLE code_strings(text); CREATE TABLE ui_strings(text_projection);"
                                 "CREATE TABLE resources(path); CREATE TABLE symbols(name);")
                db.execute("INSERT INTO code_strings VALUES (?)", ("literal_%value",))
                db.execute("INSERT INTO code_strings VALUES (?)", ("literalABvalue",))
                db.commit()
            result = query(path, term="_%")
            self.assertEqual(result["code_strings"], [{"text":"literal_%value"}])

    def test_zero_size_symbol_exact_address_is_included(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"index.sqlite"
            with closing(sqlite3.connect(path)) as db:
                db.executescript("CREATE TABLE regions(virtual_start,size);"
                                 "CREATE TABLE symbols(name,value,size);"
                                 "CREATE TABLE code_strings(virtual_address,text);")
                db.execute("INSERT INTO symbols VALUES ('zero_size_label',4096,0)")
                db.commit()
            self.assertEqual(query(path, address=4096)["symbols"][0]["name"], "zero_size_label")

    def test_query_cannot_create_missing_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"missing.sqlite"
            with self.assertRaises(FileNotFoundError):
                query(path, term="hello")
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
