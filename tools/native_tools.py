"""Pinned portable native-analysis tools; no global Java or REA configuration."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import urllib.request
import zipfile

CACHE = Path.home() / ".cache/s3300-native-analysis"
PACKAGES = {
    "ghidra": {
        "version": "12.1.4", "directory": "ghidra_12.1.4_PUBLIC",
        "archive": "ghidra_12.1.4_PUBLIC_20260921.zip",
        "url": "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip",
        "sha256": "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db",
    },
    "jdk": {
        "version": "21.0.9+10", "directory": "jdk-21.0.9+10",
        "archive": "OpenJDK21U-jdk_x64_windows_hotspot_21.0.9_10.zip",
        "url": "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.9%2B10/OpenJDK21U-jdk_x64_windows_hotspot_21.0.9_10.zip",
        "sha256": "1c67df516e9795c0b09f5714bfe151da2e3cc988082042f5bbb60d75e4e63fb5",
    },
}


def digest_file(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def checked_members(archive, destination):
    root = destination.resolve()
    for member in archive.infolist():
        name = PurePosixPath(member.filename.replace("\\", "/"))
        target = (root / Path(*name.parts)).resolve()
        mode = member.external_attr >> 16
        if (name.is_absolute() or ".." in name.parts or not target.is_relative_to(root)
                or (name.parts and ":" in name.parts[0]) or mode & 0xf000 == 0xa000):
            raise ValueError("Unsafe tool archive member")
        yield member


def ensure_package(name, cache=CACHE):
    spec = PACKAGES[name]
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / spec["archive"]
    if not archive.exists():
        temporary = archive.with_suffix(archive.suffix + ".download")
        # A failed download is not a valid cache entry; a later run retries it.
        request = urllib.request.Request(spec["url"], headers={"User-Agent": "s3300-firmware-lab"})
        print(f"Downloading verified {name} {spec['version']}", flush=True)
        with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output, 1024 * 1024)
        if digest_file(temporary) != spec["sha256"]:
            raise ValueError(f"{name} download SHA-256 differs; untrusted file retained as .download")
        temporary.replace(archive)
    if digest_file(archive) != spec["sha256"]:
        raise ValueError(f"Cached {name} archive SHA-256 differs")
    destination = cache / spec["directory"]
    marker = destination / ".s3300-extraction.json"
    if not marker.exists():
        if destination.exists():
            raise ValueError(f"Unmarked/partial installation at {destination}; preserve it and choose a new cache")
        with zipfile.ZipFile(archive) as package:
            members = list(checked_members(package, cache))
            if any(PurePosixPath(m.filename).parts[0] != spec["directory"] for m in members):
                raise ValueError("Tool archive top directory differs")
            package.extractall(cache, members=members)
        marker.write_text(json.dumps({"archive_sha256": spec["sha256"], "version": spec["version"]}) + "\n")
    if json.loads(marker.read_text())["archive_sha256"] != spec["sha256"]:
        raise ValueError("Tool extraction marker differs")
    return destination


def inspect(cache=CACHE):
    ghidra = cache / PACKAGES["ghidra"]["directory"]
    java = cache / PACKAGES["jdk"]["directory"]
    paths = {"ghidra_home": ghidra, "java_home": java,
             "java": java / "bin/java.exe", "headless": ghidra / "support/analyzeHeadless.bat",
             "decompiler": ghidra / "Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe"}
    required = ("java", "headless", "decompiler")
    ready = all(paths[key].is_file() for key in required)
    return {"ready": ready, "paths": {k: str(v) for k, v in paths.items()},
            "versions": {k: v["version"] for k, v in PACKAGES.items()},
            "file_sha256": {k: digest_file(paths[k]) for k in required if paths[k].is_file()},
            "global_configuration_changed": False,
            "scope": "Portable host analysis tooling; target firmware is never executed"}


def environment(cache=CACHE):
    report = inspect(cache)
    if not report["ready"]:
        raise ValueError("Native tools missing; run s3300.py native-setup")
    env = dict(os.environ)
    env["JAVA_HOME"] = report["paths"]["java_home"]
    env["JAVA_HOME_OVERRIDE"] = report["paths"]["java_home"]
    env["PATH"] = str(Path(report["paths"]["java_home"]) / "bin") + os.pathsep + env.get("PATH", "")
    env["MAXMEM"] = "4096M"
    return env, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=CACHE)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if not args.check:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda name: ensure_package(name, args.cache), PACKAGES))
    report = inspect(args.cache)
    if report["ready"]:
        run = subprocess.run([report["paths"]["java"], "-version"], capture_output=True, text=True, timeout=30)
        report["java_version_output"] = (run.stderr + run.stdout).strip()
        if run.returncode:
            raise ValueError("Portable JDK does not run")
    print(json.dumps(report, indent=2))
    if not report["ready"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
