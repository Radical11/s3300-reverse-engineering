"""Interface lookup, closed trial packaging, observations and honest readiness."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from uuid import uuid4

from flash_trial_payloads import TRIALS, load_trial, check_image, BASELINE

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ("menu-label", "saved-photo-effect", "standard-color", "cold-restart", "playback",
          "settings-persistence", "normal-rollback")
RESOURCE_CHECKS = CHECKS[:6]


def sha(body):
    return hashlib.sha256(body).hexdigest()


def interface_catalog(term=None, identifier=None, root=ROOT):
    path = root / "firmware/sdk/interfaces.json"
    catalog = json.loads(path.read_text(encoding="utf-8"))
    if identifier is not None:
        catalog["interfaces"] = [item for item in catalog["interfaces"] if item["id"] == identifier]
        if not catalog["interfaces"]:
            raise ValueError("Unknown interface ID")
    elif term:
        catalog["interfaces"] = [item for item in catalog["interfaces"] if term.casefold() in json.dumps(item).casefold()]
    return catalog


def record_result(trial, check, outcome, notes, *, sample=None, root=ROOT):
    if trial not in TRIALS or check not in CHECKS or outcome not in ("pass", "fail", "unknown") or not notes.strip():
        raise ValueError("Use a registered trial, documented check, outcome and observation notes")
    result = {"schema_version": 1, "trial": trial, "check": check, "outcome": outcome,
              "intended_candidate_sha256": TRIALS[trial]["sha256"], "installed_image_sha256": None,
              "observation_source": "user-reported camera observation", "notes": notes,
              "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
              "target_firmware_execution_observed_by_tool": False,
              "scope": "An observation does not establish the exact installed bytes or unbootable recovery"}
    if sample:
        path = Path(sample).resolve(strict=True)
        if not path.is_relative_to((root / "samples").resolve()):
            raise ValueError("Keep private trial samples under ignored samples/")
        result["sample"] = {"relative_path": path.relative_to(root).as_posix(), "sha256": sha(path.read_bytes())}
    directory = root / "evidence/trial-results"
    directory.mkdir(parents=True, exist_ok=True)
    filename = directory / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid4().hex[:10] + ".json")
    with filename.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2); handle.write("\n")
    return {"record": str(filename), **result}


def observations(root=ROOT):
    records = []
    for path in (root / "evidence/trial-results").glob("*.json"):
        item = json.loads(path.read_text(encoding="utf-8"))
        if (item.get("trial") in TRIALS and item.get("intended_candidate_sha256") == TRIALS[item["trial"]]["sha256"]
                and item.get("check") in CHECKS and item.get("outcome") in ("pass", "fail", "unknown")):
            records.append(item)
    return sorted(records, key=lambda item: item["recorded_at_utc"])


def dependency_status(gates, root=ROOT):
    path = root / "firmware/sdk/dependencies.json"
    if not path.is_file(): return {"available": False, "features": []}
    body = path.read_bytes(); catalog = json.loads(body)
    if catalog.get("schema_version") != 1 or catalog.get("source_sha256") != BASELINE:
        raise ValueError("Dependency ledger source identity or schema differs")
    features = []; seen = set()
    for item in catalog["features"]:
        identifier, required = item["id"], item["requires"]
        if identifier in seen or not required or len(required) != len(set(required)):
            raise ValueError("Duplicate feature or invalid dependency list")
        seen.add(identifier)
        if any(name not in gates for name in required): raise ValueError("Unknown dependency gate")
        blocked = [name for name in required if gates[name]["passed"] is not True]
        features.append({**item, "ready_within_stated_scope": not blocked, "blocked_by": blocked})
    return {"available": True, "path": "firmware/sdk/dependencies.json", "sha256": sha(body), "features": features}


def readiness(root=ROOT):
    current = {}
    for observation in observations(root):
        current[(observation["trial"], observation["check"])] = observation
    checks = {check: current.get(("amber-mono", check), {"outcome": "unknown", "notes": "No recorded observation"})
              for check in CHECKS}
    source = root / "sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    verified_source = source.is_file() and sha(source.read_bytes()) == BASELINE
    # A host-compiled binary or successful normal update cannot prove a boot-independent
    # recovery path. These gates remain blocked until that separate proof is implemented.
    gates = {
        "original_source_authenticated": {"passed": verified_source, "evidence": "original SHA-256"},
        "saved_photo_feature": {"passed": all(checks[c]["outcome"] == "pass" for c in RESOURCE_CHECKS),
                                 "checks": {c: checks[c]["outcome"] for c in RESOURCE_CHECKS}},
        "capture_buffer_abi": {"passed": False, "reason": "Scanner-to-still/JPEG routing and distinct layout/input-kind pitch arithmetic traced; live mode, component order/range, allocation extent and cache ownership remain unverified", "evidence": "evidence/shutter-input.json; evidence/shutter-route.json; evidence/pixel-layout.json; evidence/saved-jpeg-path.json; evidence/cache-dma-contracts.json"},
        "executable_hook_placement": {"passed": False, "reason": "Startup/stack/heap exclusions and path-specific cache pairs recovered; no approved placement, complete hook or general code-publication sequence", "evidence": "evidence/executable-contracts.json; evidence/cache-dma-contracts.json"},
        "complete_backup": {"passed": False, "reason": "Ordinary PTP file snapshot is separate from installed flash backup. UI/calibration layouts and bounded geometry getter recovered; no safe host memory bridge, full calibration/ECC coverage or installed geometry. Initializer fallback and updater backup paths can erase/program flash", "evidence": "evidence/backup-scope.json; evidence/backup-usb-contracts.json; evidence/camera-file-backup-2026-10-25.json; evidence/update-write-scope.json"},
        "unbootable_software_recovery": {"passed": False, "reason": "Normal menu update enters application-resident burn code. Separate reboot helper reaches ROM bfc00664 absent from supplied mappings; reset-independent activation, backup and restore remain unverified", "evidence": "evidence/updater-handoff.json; evidence/reset-recovery.json; evidence/recovery-transport.json"},
        "selectable_control_lifecycle": {"passed": False, "reason": "Existing five-entry menu and global dynamic-list ownership traced; cancel can stage/persist settings. Custom registration, bounds, Original bypass and persistence/error lifecycle remain unverified", "evidence": "evidence/menu-lifecycle.json; evidence/state-contracts.json"},
        "matched_camera_performance": {"passed": False, "reason": "No repeated matched camera baseline and candidate timings establishing improvement", "evidence": "notes/performance-protocol.md"},
    }
    sdk_evidence = root / "evidence/sdk-validation.json"
    sdk = json.loads(sdk_evidence.read_text()) if sdk_evidence.is_file() else None
    if sdk is not None:
        expected={**sdk.get("source_hashes",{}),**sdk.get("build_tools_hashes",{})}
        sdk={**sdk,"current_sources_match":bool(expected) and all((root/name).is_file() and sha((root/name).read_bytes())==digest for name,digest in expected.items()),
             "recorded_artifact_present":(root/sdk.get("artifact_relative_path","missing-sdk-artifact")).is_file()}
        artifact=(root/sdk.get("artifact_relative_path","missing-sdk-artifact")).resolve()
        sdk["recorded_artifact_hash_matches"]=(artifact.is_relative_to((root/"derived").resolve()) and artifact.is_file()
            and sha(artifact.read_bytes())==sdk.get("artifact_sha256"))
    gates["standalone_sdk_verified"]={"passed":bool(sdk and sdk.get("current_sources_match") and sdk.get("recorded_artifact_hash_matches")
        and sdk.get("emulation",{}).get("performed") and sdk.get("emulation",{}).get("reference_cases_passed")==58
        and sdk.get("two_builds_byte_identical")), "evidence":"evidence/sdk-validation.json; synthetic module only, no camera integration"}
    native_summary = root / "evidence/native-analysis.json"
    native = json.loads(native_summary.read_text()) if native_summary.is_file() else None
    native_index=root/"derived/native-index-final/manifest.json"
    index=json.loads(native_index.read_text()) if native_index.is_file() else None
    matrix=root/"evidence/matrix-application.json"
    matrix_evidence=json.loads(matrix.read_text()) if matrix.is_file() else None
    gates["static_matrix_application"]={"passed":bool(matrix_evidence and matrix_evidence.get("development_gates",{}).get("static_matrix_application_route_verified")),
        "evidence":"evidence/matrix-application.json; static register path, not a callable public ABI"}
    followups = {}
    for name in ("label-path-verification", "capture-buffers", "executable-contracts", "recovery-transport", "usb-mode-contracts", "camera-usb-verification-2026-10-25", "amber-auto-verification-2026-10-25", "saved-jpeg-path", "cache-dma-contracts", "reset-recovery", "ptp-vendor-contracts", "usb-entry-contracts", "shutter-route", "shutter-input", "pixel-layout", "menu-lifecycle", "update-write-scope", "backup-scope", "backup-usb-contracts", "updater-handoff", "application-write-scope", "camera-file-backup-2026-10-25"):
        path = root / "evidence" / (name + ".json")
        if path.is_file():
            body = path.read_bytes(); item = json.loads(body)
            followups[name] = {"evidence": path.relative_to(root).as_posix(), "sha256": sha(body),
                               "matches_source_identity": item.get("source_sha256") == BASELINE,
                               "scope": "Source-bound analysis or explicitly identified camera observations; each report states its evidence type and limits"}
    label = root / "evidence/label-path-verification.json"
    label_report = json.loads(label.read_text()) if label.is_file() else None
    gates["static_english_label_selection"] = {
        "passed": bool(label_report and label_report.get("source_sha256") == BASELINE and
                       label_report.get("development_gates", {}).get("static_english_color_label_path_verified")),
        "evidence": "evidence/label-path-verification.json; runtime confirmation is recorded separately in the trial ledger"}
    resource_ready = verified_source and gates["saved_photo_feature"]["passed"]
    from camera_backup import backup_status
    return {"schema_version": 1, "source_sha256": BASELINE, "resource_ready": resource_ready,
            "backup_coverage": backup_status(root),
            "code_ready": False, "complete": False, "gates": gates, "amber_checks": checks,
            "sdk_host_evidence": sdk, "native_analysis": native,"native_index":index,
            "matrix_application_evidence":matrix_evidence, "research_followups": followups,
            "feature_dependencies":dependency_status(gates,root),
            "normal_rollback_observed": checks["normal-rollback"]["outcome"] == "pass",
            "executable_trials_allowed": False, "software_only": True,
            "note": "Recovery gate cannot be promoted by an ordinary rollback, host test, artifact count or user result entry"}


def save_readiness(root=ROOT):
    report = readiness(root)
    target = root / "evidence/development-readiness.json"
    target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def require_amber_identity(root=ROOT):
    prior = root / "derived/pocket-studio-identity-candidate-01/NOT-INSTALLABLE-patch-plan.research.bin"
    if not prior.is_file():
        raise ValueError("Amber validation needs the reviewed Pocket Studio base. Rebuild it once using docs/development/06-amber.md before validation")
    if sha(prior.read_bytes()) != "8f742b9a699b276a001827721fab4bd50e578372a582acc020ba1caa6e75754c":
        raise ValueError("Reviewed Pocket Studio base hash differs; preserve it and follow docs/development/06-amber.md")
    return prior


def validate_trial(trial, *, candidate=None, output=None, root=ROOT):
    if trial not in TRIALS:
        raise ValueError("Unknown closed-registry trial")
    source = (root / "sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes()
    path = Path(candidate).resolve() if candidate else root / TRIALS[trial]["path"]
    body = check_image(source, path.read_bytes(), TRIALS[trial]["sha256"])
    if trial == "resource-label":
        from validate_resource_candidate import verify
        independent = verify(source, body)
    elif trial == "pocket-studio":
        from validate_startup_trial import verify
        prior = (root / TRIALS["embedded-label"]["path"]).read_bytes()
        filesystem = json.loads((root / "evidence/resource-filesystem.json").read_text())
        independent = verify(prior, body, filesystem["entries"])
    elif trial == "amber-mono":
        require_amber_identity(root)
        if output is None:
            output = root / "derived/trial-validation" / (uuid4().hex + ".json")
        output = Path(output).resolve()
        if not output.is_relative_to((root / "derived").resolve()) or output.exists():
            raise ValueError("Validation output must be a new path under derived/")
        output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([sys.executable, str(root / "tools/validate_amber_trial.py"), str(path),
                        "--evidence", str(output)], cwd=root, check=True, capture_output=True, text=True)
        independent = json.loads(output.read_text())
    else:
        # This older trial has construction/paired-decoder evidence, but lacks a
        # standalone full validator callable here. Do not silently downgrade.
        raise ValueError("Embedded-label has no standalone packaging validator; use the independently validated Pocket Studio or Amber trial")
    return {"trial": trial, "candidate_sha256": sha(body), "candidate_bytes": len(body),
            "independent_validation": independent, "camera_accessed": False,
            "runtime_verified": False, "recovery_verified": False}


def prepare_trial(trial, output, *, root=ROOT):
    output = Path(output).resolve()
    if not output.is_relative_to((root / "derived").resolve()) or output.exists():
        raise ValueError("Choose a new local package directory under derived/")
    validation = validate_trial(trial, root=root)
    output.mkdir(parents=True)
    source = root / TRIALS[trial]["path"]
    folder = output / "firmware"; folder.mkdir()
    target = folder / "firmware.bin"
    with target.open("xb") as handle: handle.write(source.read_bytes())
    if sha(target.read_bytes()) != validation["candidate_sha256"]:
        raise ValueError("Prepared package readback differs")
    report = {**validation, "phase": "local reviewed-trial package only", "card_written": False,
              "camera_flashed": False, "executable_code_changes": False,
              "readiness": {"resource_ready": False, "code_ready": False},
              "observation_results": [r for r in observations(root) if r["trial"] == trial]}
    (output / "trial-manifest.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "README.txt").write_text("LOCAL EXPERIMENT PACKAGE\nNo card transfer or camera update was performed.\n"
        "Preserve current photo/update backups. Use only the reviewed normal camera update path.\n"
        "A valid package does not establish installation, behavior or unbootable recovery.\n")
    return report
