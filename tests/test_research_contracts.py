"""Research reruns retain source checks and refuse stale or public outputs."""
from pathlib import Path
import hashlib
import json
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import research_contracts as research


class ResearchContractsTests(unittest.TestCase):
    def test_public_path_rejected_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(research.importlib, 'import_module') as load:
                with self.assertRaisesRegex(ValueError, 'derived'):
                    research.run('saved-jpeg', root / 'public.json', root, root=root)
                load.assert_not_called()

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / 'derived/map.json'
            output.parent.mkdir(); output.write_text('keep')
            with self.assertRaisesRegex(ValueError, 'new research output'):
                research.run('cache-dma', output, root, root=root)
            self.assertEqual(output.read_text(), 'keep')

    def test_changed_current_report_rejected_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / 'derived/map.json'
            output.parent.mkdir(); output.write_text('{"source_sha256":"old"}')
            module = SimpleNamespace(build_report=lambda *args: {'source_sha256': 'new'})
            with patch.object(research.importlib, 'import_module', return_value=module), patch.object(research, 'provenance', return_value={}):
                with self.assertRaisesRegex(ValueError, 'stale or incompatible'):
                    research.run('reset-recovery', output, root, verify_existing=True, root=root)
            self.assertEqual(json.loads(output.read_text())['source_sha256'], 'old')

    def test_recheck_compares_inputs_and_does_not_rewrite_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / 'derived/map.json'
            report = {'source_sha256': 'synthetic', 'native': {'dossier_sha256': 'fixture'}}
            module = SimpleNamespace(build_report=lambda *args: report)
            with patch.object(research.importlib, 'import_module', return_value=module), patch.object(research, 'provenance', return_value={}):
                first = research.run('ptp-vendor', output, root / 'baseline', root=root)
                original = output.read_bytes()
                second = research.run('ptp-vendor', output, root / 'baseline', verify_existing=True, root=root)
            self.assertFalse(first['camera_accessed']); self.assertTrue(second['verified_existing'])
            self.assertEqual(output.read_bytes(), original)

    def test_failed_authentication_leaves_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root / 'derived/map.json'
            def fail(*args): raise ValueError('Source differs')
            with patch.object(research.importlib, 'import_module', return_value=SimpleNamespace(build_report=fail)):
                with self.assertRaisesRegex(ValueError, 'Source differs'):
                    research.run('saved-jpeg', output, root, root=root)
            self.assertFalse(output.exists())

    def test_provenance_rejects_changed_native_tool_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); profile=root/'derived/native-analysis-complete/profile.json'
            profile.parent.mkdir(parents=True)
            profile.write_text(json.dumps({'source_sha256':'source','analysis_sha256':'analysis',
                'tools':{'versions':{'ghidra':'different','jdk':'21.0.9+10'}}}))
            with self.assertRaisesRegex(ValueError,'profile is incompatible'):
                research.provenance('saved-jpeg',{'source_sha256':'source','analysis_sha256':'analysis'},root)

    def test_provenance_rejects_changed_exporter_before_reading_other_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); profile=root/'derived/native-analysis-complete/profile.json'
            profile.parent.mkdir(parents=True); script=root/'tools/ghidra/Export.java'
            script.parent.mkdir(parents=True); script.write_bytes(b'changed')
            profile.write_text(json.dumps({'source_sha256':'source','analysis_sha256':'analysis',
                'tools':{'versions':{'ghidra':'12.1.4','jdk':'21.0.9+10'}},
                'scripts':{'Export.java':hashlib.sha256(b'original').hexdigest()}}))
            with self.assertRaisesRegex(ValueError,'exporter script differs'):
                research.provenance('saved-jpeg',{'source_sha256':'source','analysis_sha256':'analysis'},root)


if __name__ == '__main__': unittest.main()
