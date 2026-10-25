"""Reuse the extracted S3300 baseline through one offline development CLI."""
import argparse
from contextlib import closing
from importlib import metadata
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
BASELINE = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
DEFAULT_WORKSPACE = ROOT / "derived/unpacked-v1.1-indexed"
CATALOG = ROOT / "hardware/s3300.json"
DEPENDENCIES = {"pyelftools": "0.33", "capstone": "5.0.6", "Pillow": "12.3.0"}


def sha(body):
    return hashlib.sha256(body).hexdigest()


def run_tool(script, *args):
    subprocess.run([sys.executable, str(ROOT / "tools" / script), *map(str, args)],
                   cwd=ROOT, check=True)


def local_file(workspace, relative):
    """Require inventory paths to remain inside the selected local workspace."""
    relative = Path(relative)
    target = (workspace / relative).resolve()
    if relative.is_absolute() or not target.is_relative_to(workspace.resolve()):
        raise ValueError("Inventory path escapes workspace")
    return target


def verify_workspace(workspace):
    """Check stored artifacts without repeating extraction or decompression.

    Carrier and analysis have fixed known digests. Resource exports are checked
    against the reconstructed carrier, and decoded outputs against the trusted
    analysis image. SQLite integrity/counts are checked, not every indexed row.
    """
    from unpack_workspace import verify_partition
    from workspace_functions import load_analysis, recover_ranges
    from resource_formats import encode_zst, encode_zbm

    partition = verify_partition(workspace)
    carrier_manifest = json.loads((workspace / "unpacked.json").read_text(encoding="utf-8"))
    carrier = b"".join(local_file(workspace, p["file"]).read_bytes()
                       for p in carrier_manifest["carrier_parts"])
    analysis, raw = load_analysis(workspace)
    functions, _, _ = recover_ranges(workspace)
    inventory = json.loads((workspace / "resource-inventory.json").read_text(encoding="utf-8"))
    seen = set()
    editable = 0
    for record in inventory["files"]:
        if record["path"] in seen:
            raise ValueError("Duplicate resource inventory path")
        seen.add(record["path"])
        body = local_file(workspace / "resources", record["path"]).read_bytes()
        chunks = []
        for chunk in record["source_chunks"]:
            start, count = chunk["carrier_offset"], chunk["file_bytes"]
            if start < 0 or count <= 0 or start + count > len(carrier):
                raise ValueError("Resource source chunk exceeds carrier")
            chunks.append(carrier[start:start + count])
        if (body != b"".join(chunks) or len(body) != record["bytes"]
                or sha(body) != record["sha256"]):
            raise ValueError(f"Resource differs from source chunks: {record['path']}")
        if "editable_document" in record:
            document = json.loads(local_file(workspace, record["editable_document"]).read_text(encoding="utf-8"))
            if document["format"] == "s3300-zst":
                rebuilt = encode_zst(document)
            elif document["format"] == "s3300-zbm-indices":
                rebuilt = encode_zbm(document)
            else:
                raise ValueError("Unknown editable resource format")
            if rebuilt != body:
                raise ValueError(f"Baseline export has edits: {record['path']}; edit a separate copy")
            editable += 1
    if len(seen) != 368 or editable != 106:
        raise ValueError("Incomplete baseline resource/export inventory")
    decoded = 0
    for region in analysis["regions"]:
        if not region["name"].startswith(".decoded_"):
            continue
        offset, size = region["analysis_elf_offset"], region["size"]
        expected = raw[offset:offset + size]
        production = workspace / "decoded" / f"segment-{region['carrier_offset']:08x}.bin"
        independent = workspace / "independent" / f"segment-{region['virtual_start']:08x}.bin"
        if production.read_bytes() != expected or independent.read_bytes() != expected:
            raise ValueError("Stored decoder outputs differ from authenticated analysis image")
        decoded += size
    if decoded != 7950592:
        raise ValueError("Incomplete decoded application coverage")
    uri = (workspace / "research.sqlite").resolve(strict=True).as_uri() + "?mode=ro"
    expected_counts = {"regions": 8, "code_strings": 26976, "symbols": 1924,
                       "resources": 368, "ui_strings": 98085, "functions": len(functions)}
    with closing(sqlite3.connect(uri, uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("Search database integrity check failed")
        if db.execute("SELECT value FROM metadata WHERE key='source_sha256'").fetchone() != (BASELINE,):
            raise ValueError("Search database source identity differs")
        for table, count in expected_counts.items():
            if db.execute(f"SELECT count(*) FROM {table}").fetchone()[0] != count:
                raise ValueError(f"Search index coverage differs: {table}")
    return {"carrier": partition, "authenticated_analysis": True,
            "decoded_bytes_compared": decoded, "resources_checked": len(seen),
            "editable_roundtrips_checked": editable, "search_index_counts": expected_counts,
            "index_check_scope": "SQLite integrity, source metadata and row counts; not full row semantics",
            "camera_runtime_validated": False}


def doctor(workspace):
    # Match the existing disassembly tools' project-local dependency location.
    vendor = str(ROOT / "tools/vendor")
    if vendor not in sys.path:
        sys.path.insert(0, vendor)
    report = {"python": sys.version.split()[0], "python_supported": sys.version_info[:2] == (3, 13),
              "dependencies": {}, "source_present": SOURCE.is_file(), "workspace_present": workspace.is_dir()}
    from native_tools import inspect as inspect_native
    report["native_analysis_tools"]=inspect_native()
    try:
        from build_sdk import check_toolchain
        report["sdk_toolchain"]=check_toolchain()
    except (ImportError,OSError,ValueError) as exc:
        report["sdk_toolchain"]={"ready":False,"reason":str(exc)}
    errors = []
    if not report["python_supported"]:
        errors.append("Use Python 3.13, the version covered by project CI")
    for package, expected in DEPENDENCIES.items():
        try:
            actual = metadata.version(package)
        except metadata.PackageNotFoundError:
            actual = None
        report["dependencies"][package] = {"expected": expected, "installed": actual}
        if actual != expected:
            errors.append(f"Install {package}=={expected} in the active virtual environment")
    if not SOURCE.is_file() or sha(SOURCE.read_bytes()) != BASELINE:
        errors.append("Original supplied v1.1 firmware missing or hash differs; see notes/developer-workspace.md")
    if not workspace.is_dir():
        errors.append("Workspace missing; run s3300.py init after placing the original source")
    elif not any(v["installed"] != v["expected"] for v in report["dependencies"].values()):
        try:
            report["workspace_verification"] = verify_workspace(workspace)
        except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
            errors.append(f"Workspace check failed: {exc}")
    report.update(ready=not errors, errors=errors, camera_accessed=False)
    return report


def initialize(workspace):
    if not workspace.resolve().is_relative_to((ROOT / "derived").resolve()):
        raise ValueError("Keep vendor artifacts in a workspace under derived/")
    if workspace.exists():
        return {"reused": True, "verification": verify_workspace(workspace)}
    run_tool("unpack_workspace.py", workspace)
    return {"reused": False, "verification": verify_workspace(workspace)}


def load_catalog(term=None):
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    if term:
        catalog["entries"] = [e for e in catalog["entries"]
                              if term.casefold() in json.dumps(e).casefold()]
    return catalog


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Read-only dependency, source and stored-workspace verification")
    browse = commands.add_parser("browse", help="Serve a read-only localhost workbench for retained functions, interfaces and readiness")
    browse.add_argument("--port", type=int, default=0, help="Local port;0 selects an available port")
    browse.add_argument("--database", type=Path, help="Native/artifact index; default prefers retained artifact namespaces")
    browse.add_argument("--check", action="store_true", help="Check datasets without starting a server")
    commands.add_parser("init", help="Extract once; reuse and verify an existing workspace")
    limits = commands.add_parser("limits", help="Hardware, stock limits, development capabilities and unknowns")
    limits.add_argument("--search")
    limits.add_argument("--json", action="store_true")
    search = commands.add_parser("search", help="Literal search of the extracted baseline")
    search.add_argument("term")
    search.add_argument("--limit", type=int, default=20)
    address = commands.add_parser("address", help="Region, symbol and function lookup")
    address.add_argument("value", type=lambda value: int(value, 0))
    listing = commands.add_parser("listing", help="Export a bounded function listing to a new file")
    listing.add_argument("value", type=lambda value: int(value, 0))
    listing.add_argument("output", type=Path)
    build = commands.add_parser("build", help="Build an offline candidate from a fixed-extent patch plan")
    build.add_argument("plan", type=Path)
    build.add_argument("output", type=Path)
    atlas_build = commands.add_parser("atlas-build", help="Map all known function ranges and references into a new offline atlas")
    atlas_build.add_argument("output", type=Path)
    atlas = commands.add_parser("atlas", help="Query the static function/reference/subsystem atlas")
    atlas.add_argument("--database", type=Path, default=ROOT / "derived/firmware-atlas-v1.1/atlas.sqlite")
    selection = atlas.add_mutually_exclusive_group(required=True)
    selection.add_argument("--address", type=lambda value: int(value, 0))
    selection.add_argument("--search")
    selection.add_argument("--subsystem")
    atlas.add_argument("--limit", type=int, default=20)
    atlas.add_argument("--assembly", action="store_true", help="Include full stored linear listing for an address")
    commands.add_parser("native-setup", help="Install hash-verified portable Ghidra and JDK in the dedicated cache")
    native = commands.add_parser("native-analyze", help="Retained direct Ghidra analysis; no target execution")
    native.add_argument("output", type=Path)
    native.add_argument("--decompile-limit", type=int, default=-1)
    native.add_argument("--resume", action="store_true")
    native.add_argument("--image", action="append")
    retry = commands.add_parser("native-retry", help="Retry one failed function without deleting its original failure record")
    retry.add_argument("analysis", type=Path)
    retry.add_argument("--address", required=True)
    retry.add_argument("--timeout", type=int, default=120)
    native_index = commands.add_parser("native-index", help="Byte-check and index a completed application decompilation")
    native_index.add_argument("analysis", type=Path)
    native_index.add_argument("output", type=Path)
    artifact_index = commands.add_parser("artifact-index", help="Index retained application and separate executables with isolated address namespaces")
    artifact_index.add_argument("output", type=Path)
    artifact_index.add_argument("--native", type=Path, default=ROOT/"derived/native-analysis-complete")
    artifact_index.add_argument("--application-index", type=Path, default=ROOT/"derived/native-index-final/native.sqlite")
    artifact_index.add_argument("--application-writer-focus", type=Path, help="Optional authenticated focused writer export; preserves caller-seeded boundary warning")
    artifact_function = commands.add_parser("artifact-function", help="Query a function within one executable namespace")
    artifact_function.add_argument("--database", type=Path, default=(ROOT/"derived/artifact-function-index-current/native.sqlite" if (ROOT/"derived/artifact-function-index-current/native.sqlite").is_file() else ROOT/"derived/artifact-function-index-v1.1/native.sqlite"))
    artifact_function.add_argument("--image", default="application")
    artifact_selection = artifact_function.add_mutually_exclusive_group(required=True)
    artifact_selection.add_argument("--address", type=lambda value:int(value,0))
    artifact_selection.add_argument("--search")
    artifact_function.add_argument("--limit", type=int, default=30)
    pseudo = commands.add_parser("pseudocode", help="Read-only lookup in the retained native index")
    pseudo.add_argument("--database", type=Path, default=ROOT/"derived/native-index-final/native.sqlite")
    choice = pseudo.add_mutually_exclusive_group(required=True)
    choice.add_argument("--address", type=lambda value:int(value,0))
    choice.add_argument("--search")
    pseudo.add_argument("--limit", type=int, default=20)
    interface = commands.add_parser("interface", help="Look up recovered contracts and unresolved integration gates")
    selection = interface.add_mutually_exclusive_group()
    selection.add_argument("--search")
    selection.add_argument("--id")
    from research_contracts import TOPICS
    research = commands.add_parser("research-map", help="Recheck a focused contract map using retained native analysis; no camera access")
    research.add_argument("topic", choices=tuple(TOPICS))
    research.add_argument("output", type=Path)
    research.add_argument("--verify-existing", action="store_true", help="Recompute source-bound checks and reject a stale report")
    sdk = commands.add_parser("sdk-build", help="Build and inspect the freestanding target module; no firmware insertion")
    sdk.add_argument("output", type=Path)
    sdk.add_argument("--install-toolchain", action="store_true")
    validate = commands.add_parser("validate-candidate", help="Independently validate an exact closed-registry trial")
    validate.add_argument("trial")
    validate.add_argument("--candidate", type=Path)
    package = commands.add_parser("prepare-trial", help="Prepare a local reviewed card-layout package; no transfer")
    package.add_argument("trial")
    package.add_argument("output", type=Path)
    result = commands.add_parser("record-result", help="Record a user-observed camera check; never promotes recovery")
    result.add_argument("trial")
    result.add_argument("--check", required=True)
    result.add_argument("--outcome", choices=("pass", "fail", "unknown"), required=True)
    result.add_argument("--notes", required=True)
    result.add_argument("--sample", type=Path)
    results = commands.add_parser("results", help="Read recorded trial observations")
    results.add_argument("--trial")
    ready = commands.add_parser("readiness", help="Report resource/code readiness and unresolved gates")
    ready.add_argument("--json", action="store_true")
    camera_usb = commands.add_parser("camera-usb", help="Read connected S3300 USB descriptors through the existing Windows hub driver")
    camera_usb.add_argument("output", type=Path, help="New metadata report under derived/; no vendor commands or writes")
    metadata = commands.add_parser("camera-metadata", help="Read standard PTP device/storage/object metadata with the existing Windows driver")
    metadata.add_argument("output", type=Path, help="New private report under derived/")
    backup_files = commands.add_parser("backup-files", help="Twice-read snapshot of visible PTP files; not installed flash/calibration backup")
    backup_files.add_argument("output", type=Path, help="New ignored samples/ directory;64MiB per file,512MiB total")
    verify_files = commands.add_parser("verify-file-backup", help="Recheck a local PTP file snapshot without contacting the camera")
    verify_files.add_argument("output", type=Path)
    backup_info = commands.add_parser("backup-status", help="Show backup component coverage; optional local file recheck, no device access")
    backup_info.add_argument("--verify-files", action="store_true")
    store_info = commands.add_parser("inspect-store", help="Inspect an already acquired settings/calibration store; no acquisition, repair or restore")
    store_info.add_argument("kind", choices=("ui","calibration"))
    store_info.add_argument("input", type=Path)
    guide = commands.add_parser("guide", help="Build an offline navigable development guide")
    guide.add_argument("output", type=Path)
    package_source = commands.add_parser("package-development", help="Build a local source-only development archive")
    package_source.add_argument("output", type=Path)
    commands.add_parser("test", help="Run the offline test suite; no camera connection")
    args = parser.parse_args(argv)
    args.workspace = args.workspace.resolve()
    try:
        if args.command == "doctor":
            result = doctor(args.workspace)
            print(json.dumps(result, indent=2))
            return 0 if result["ready"] else 1
        if args.command == "init":
            print(json.dumps(initialize(args.workspace), indent=2))
        elif args.command == "browse":
            from workbench_server import Workbench, serve
            if args.check:
                print(json.dumps(Workbench(ROOT,args.database).status(), indent=2))
            else:
                serve(args.port, ROOT, args.database)
        elif args.command == "limits":
            catalog = load_catalog(args.search)
            if args.json:
                print(json.dumps(catalog, indent=2))
            else:
                print(f"{catalog['model']} | checked {catalog['checked_date']}\n{catalog['scope']}\n")
                for entry in catalog["entries"]:
                    value = "Unknown" if entry["value"] is None else entry["value"]
                    print(f"{entry['id']} [{entry['evidence_level']}; {entry['kind']}]\n"
                          f"  {value}\n  {entry['constraint']}\n"
                          f"  Evidence: {', '.join(entry['sources'])}\n")
        elif args.command in ("search", "address"):
            from query_workspace import query
            kwargs = {"term": args.term, "limit": args.limit} if args.command == "search" else {"address": args.value}
            print(json.dumps(query(args.workspace / "research.sqlite", **kwargs), indent=2))
        elif args.command == "listing":
            run_tool("workspace_functions.py", args.workspace, "--listing", hex(args.value), "--output", args.output.resolve())
        elif args.command == "build":
            run_tool("build_patch_candidate.py", args.plan.resolve(), args.output.resolve(),
                     "--workspace", args.workspace.resolve())
        elif args.command == "atlas-build":
            run_tool("map_firmware_atlas.py", args.output.resolve(), "--workspace", args.workspace)
        elif args.command == "atlas":
            from map_firmware_atlas import query
            print(json.dumps(query(args.database, address=args.address, term=args.search,
                                   subsystem=args.subsystem, limit=args.limit,
                                   include_assembly=args.assembly), indent=2))
        elif args.command == "native-setup":
            run_tool("native_tools.py")
        elif args.command == "native-analyze":
            parameters = [args.output.resolve(), "--workspace", args.workspace, "--decompile-limit", args.decompile_limit]
            if args.resume:
                parameters.append("--resume")
            for image in args.image or []:
                parameters.extend(["--image", image])
            run_tool("native_analysis.py", *parameters)
        elif args.command == "native-retry":
            run_tool("retry_native_analysis.py",args.analysis.resolve(),"--address",args.address,"--timeout",args.timeout)
        elif args.command == "interface":
            from development_platform import interface_catalog
            print(json.dumps(interface_catalog(args.search, args.id), indent=2))
        elif args.command == "research-map":
            from research_contracts import run
            print(json.dumps(run(args.topic, args.output, args.workspace,
                                 verify_existing=args.verify_existing), indent=2))
        elif args.command == "native-index":
            from index_native_analysis import build
            print(json.dumps(build(args.analysis,args.output,args.workspace),indent=2))
        elif args.command == "artifact-index":
            from index_artifact_functions import build
            print(json.dumps(build(args.native,args.application_index,args.workspace,args.output,
                                   application_writer_focus=args.application_writer_focus),indent=2))
        elif args.command == "artifact-function":
            from index_artifact_functions import query
            print(json.dumps(query(args.database,image=args.image,address=args.address,term=args.search or '',limit=args.limit),indent=2))
        elif args.command == "pseudocode":
            from index_native_analysis import query
            print(json.dumps(query(args.database,address=args.address,term=args.search,limit=args.limit),indent=2))
        elif args.command == "sdk-build":
            parameters = [args.output.resolve()]
            if args.install_toolchain:
                parameters.append("--install-toolchain")
            run_tool("build_sdk.py", *parameters)
        elif args.command == "validate-candidate":
            from development_platform import validate_trial
            print(json.dumps(validate_trial(args.trial, candidate=args.candidate), indent=2))
        elif args.command == "prepare-trial":
            from development_platform import prepare_trial
            print(json.dumps(prepare_trial(args.trial, args.output), indent=2))
        elif args.command == "record-result":
            from development_platform import record_result, save_readiness
            print(json.dumps(record_result(args.trial, args.check, args.outcome, args.notes, sample=args.sample), indent=2))
            save_readiness()
        elif args.command == "results":
            from development_platform import observations
            print(json.dumps([r for r in observations() if not args.trial or r["trial"] == args.trial], indent=2))
        elif args.command == "readiness":
            from development_platform import readiness
            report = readiness()
            if args.json:
                print(json.dumps(report, indent=2))
            else:
                print(f"Resource-ready: {report['resource_ready']} | Code-ready: {report['code_ready']}")
                for name, gate in report["gates"].items():
                    print(f"{'PASS' if gate['passed'] else 'BLOCKED'} {name}: {gate.get('reason', gate.get('checks', gate.get('evidence', '')))}")
        elif args.command in ("camera-metadata", "backup-files"):
            from camera_backup import acquire
            report = acquire(args.output, files=args.command == "backup-files")
            print(json.dumps(report, indent=2))
            return 0 if report['status'] in ('metadata_complete', 'file_snapshot_complete') else 1
        elif args.command == "verify-file-backup":
            from camera_backup import verify_snapshot
            print(json.dumps(verify_snapshot(args.output), indent=2))
        elif args.command == "backup-status":
            from camera_backup import backup_status
            print(json.dumps(backup_status(verify_files=args.verify_files), indent=2))
        elif args.command == "inspect-store":
            from map_backup_scope import inspect_store
            if args.input.stat().st_size > 0x24a: raise ValueError('Inspect one exact serialized store, not a flash image')
            print(json.dumps(inspect_store(args.input.read_bytes(), args.kind), indent=2))
        elif args.command == "camera-usb":
            output = args.output.resolve()
            if output.exists() or not output.is_relative_to((ROOT/"derived").resolve()):
                raise ValueError("Choose a new camera metadata report under derived/")
            if not output.parent.is_dir():
                raise ValueError("Camera metadata report parent must already exist")
            run_tool("read_usb_descriptors.py", "--evidence", output)
        elif args.command == "guide":
            from development_platform import save_readiness
            save_readiness()
            run_tool("build_development_guide.py", args.output.resolve())
        elif args.command == "package-development":
            from package_development import build
            print(json.dumps(build(args.output),indent=2))
        elif args.command == "test":
            subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT, check=True)
        return 0
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, ImportError, subprocess.CalledProcessError) as exc:
        print(f"Workspace error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
