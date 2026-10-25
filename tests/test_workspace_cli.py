"""Offline workspace lifecycle and evidence-boundary checks; no vendor input."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import workspace_cli as cli


class LifecycleTests(unittest.TestCase):
    def test_existing_workspace_is_verified_without_reextracting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "derived/baseline"
            workspace.mkdir(parents=True)
            sentinel = workspace / "keep.txt"
            sentinel.write_text("keep")
            with patch.object(cli, "ROOT", root), patch.object(cli, "verify_workspace", return_value={"ok": True}) as verify, patch.object(cli, "run_tool") as run:
                self.assertEqual(cli.initialize(workspace), {"reused": True, "verification": {"ok": True}})
                verify.assert_called_once_with(workspace)
                run.assert_not_called()
            self.assertEqual(sentinel.read_text(), "keep")

    def test_changed_existing_workspace_is_not_silently_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "derived/baseline"
            workspace.mkdir(parents=True)
            with patch.object(cli, "ROOT", root), patch.object(cli, "verify_workspace", side_effect=ValueError("changed baseline")), patch.object(cli, "run_tool") as run:
                with self.assertRaisesRegex(ValueError, "changed baseline"):
                    cli.initialize(workspace)
                run.assert_not_called()
            self.assertTrue(workspace.is_dir())

    def test_vendor_output_cannot_be_created_in_public_source_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(cli, "ROOT", root), patch.object(cli, "run_tool") as run:
                with self.assertRaisesRegex(ValueError, "derived"):
                    cli.initialize(root / "public-output")
                run.assert_not_called()
            self.assertFalse((root / "public-output").exists())

    def test_inventory_paths_cannot_escape_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "baseline"
            self.assertEqual(cli.local_file(workspace, "resources/example.bin"), (workspace / "resources/example.bin").resolve())
            for value in ("../secret.bin", str(Path(directory) / "secret.bin")):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "escapes"):
                    cli.local_file(workspace, value)

    def test_doctor_missing_inputs_is_read_only_and_not_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(cli, "SOURCE", root / "missing.bin"), patch.object(cli.metadata, "version", side_effect=lambda p: cli.DEPENDENCIES[p]):
                report = cli.doctor(root / "missing-workspace")
            self.assertFalse(report["ready"])
            self.assertFalse(report["camera_accessed"])
            self.assertFalse(report["source_present"])
            self.assertEqual(list(root.iterdir()), [])


class CatalogTests(unittest.TestCase):
    def test_catalog_unknowns_and_sources_are_explicit(self):
        catalog = cli.load_catalog()
        self.assertEqual(catalog["baseline_sha256"], cli.BASELINE)
        ids = [e["id"] for e in catalog["entries"]]
        self.assertEqual(len(ids), len(set(ids)))
        for entry in catalog["entries"]:
            with self.subTest(entry=entry["id"]):
                self.assertTrue(entry["constraint"])
                self.assertTrue(entry["sources"])
                if entry["evidence_level"] in ("unknown", "conflicting_sources"):
                    self.assertIsNone(entry["value"])
                for source in entry["sources"]:
                    record = catalog["sources"][source]
                    if "path" in record:
                        self.assertTrue((cli.ROOT / record["path"]).is_file())
                    else:
                        self.assertTrue(record["url"].startswith("https://"))

    def test_stock_modes_are_not_promoted_to_hardware_limits(self):
        entries = {e["id"]: e for e in cli.load_catalog()["entries"]}
        for key in ("still-burst", "movie-clip", "iso", "shutter", "video"):
            self.assertEqual(entries[key]["kind"], "stock_limit")
        for key in ("ram-capacity-and-headroom", "cpu-clock-and-model", "debug-and-recovery"):
            self.assertIsNone(entries[key]["value"])

    def test_catalog_search_does_not_need_extracted_vendor_data(self):
        result = cli.load_catalog("ram-capacity")
        self.assertEqual([e["id"] for e in result["entries"]], ["ram-capacity-and-headroom"])


if __name__ == "__main__":
    unittest.main()
