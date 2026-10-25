"""Observation provenance, closed packaging and recovery-gate separation."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import development_platform as platform


class DevelopmentPlatformTests(unittest.TestCase):
    def test_all_reported_resource_checks_do_not_prove_executable_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for check in platform.CHECKS:
                platform.record_result("amber-mono",check,"pass","synthetic user observation",root=root)
            report=platform.readiness(root)
            self.assertTrue(report["gates"]["saved_photo_feature"]["passed"])
            self.assertFalse(report["resource_ready"])  # Original source absent.
            self.assertFalse(report["code_ready"])
            self.assertFalse(report["gates"]["unbootable_software_recovery"]["passed"])
            self.assertFalse(report["executable_trials_allowed"])

    def test_new_failure_supersedes_pass_without_deleting_old_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            platform.record_result("amber-mono","menu-label","pass","earlier observation",root=root)
            platform.record_result("amber-mono","menu-label","fail","corrected after restart",root=root)
            self.assertEqual(len(platform.observations(root)),2)
            self.assertEqual(platform.readiness(root)["amber_checks"]["menu-label"]["outcome"],"fail")

    def test_mismatched_candidate_observation_is_not_promoted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            result=platform.record_result("amber-mono","menu-label","pass","observation",root=root)
            path=Path(result["record"])
            item=json.loads(path.read_text());item["intended_candidate_sha256"]="0"*64
            path.write_text(json.dumps(item))
            self.assertEqual(platform.observations(root),[])

    def test_unknown_trials_and_checks_cannot_enter_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for trial,check,outcome in (("arbitrary","menu-label","pass"),("amber-mono","recovery","pass"),("amber-mono","menu-label","maybe")):
                with self.assertRaises(ValueError):
                    platform.record_result(trial,check,outcome,"note",root=root)
            self.assertEqual(list(root.iterdir()),[])

    def test_failed_validation_prevents_package_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);output=root/"derived/trial"
            with patch.object(platform,"validate_trial",side_effect=ValueError("bad candidate")):
                with self.assertRaisesRegex(ValueError,"bad candidate"):
                    platform.prepare_trial("amber-mono",output,root=root)
            self.assertFalse(output.exists())

    def test_private_samples_cannot_escape_samples_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);sample=root/"outside.jpg";sample.write_bytes(b"private")
            with self.assertRaisesRegex(ValueError,"samples"):
                platform.record_result("amber-mono","saved-photo-effect","pass","note",sample=sample,root=root)
            self.assertFalse((root/"evidence").exists())

    def test_feature_dependencies_expose_each_unresolved_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); path=root/"firmware/sdk/dependencies.json"; path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"schema_version":1,"source_sha256":platform.BASELINE,
                "features":[{"id":"synthetic","requires":["compiled","recovery"]}]}))
            report=platform.dependency_status({"compiled":{"passed":True},"recovery":{"passed":False}},root)
            self.assertFalse(report["features"][0]["ready_within_stated_scope"])
            self.assertEqual(report["features"][0]["blocked_by"],["recovery"])

    def test_dependency_ledger_cannot_silently_reference_unknown_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); path=root/"firmware/sdk/dependencies.json"; path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"schema_version":1,"source_sha256":platform.BASELINE,
                "features":[{"id":"synthetic","requires":["invented-recovery"]}]}))
            with self.assertRaisesRegex(ValueError,"Unknown dependency"):
                platform.dependency_status({},root)

    def test_dependency_ledger_rejects_wrong_identity_and_duplicate_features(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); path=root/"firmware/sdk/dependencies.json"; path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"schema_version":1,"source_sha256":"wrong","features":[]}))
            with self.assertRaisesRegex(ValueError,"source identity"):
                platform.dependency_status({},root)
            feature={"id":"duplicate","requires":["gate"]}
            path.write_text(json.dumps({"schema_version":1,"source_sha256":platform.BASELINE,"features":[feature,feature]}))
            with self.assertRaisesRegex(ValueError,"Duplicate feature"):
                platform.dependency_status({"gate":{"passed":True}},root)

    def test_amber_missing_identity_base_reports_reproduction_prerequisite(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with self.assertRaisesRegex(ValueError,"Rebuild it once"):
                platform.require_amber_identity(root)
            self.assertEqual(list(root.iterdir()),[])

    def test_amber_wrong_identity_base_is_preserved_and_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); prior=root/"derived/pocket-studio-identity-candidate-01/NOT-INSTALLABLE-patch-plan.research.bin"
            prior.parent.mkdir(parents=True); prior.write_bytes(b"wrong identity")
            with self.assertRaisesRegex(ValueError,"base hash differs"):
                platform.require_amber_identity(root)
            self.assertEqual(prior.read_bytes(),b"wrong identity")


if __name__=="__main__":unittest.main()
