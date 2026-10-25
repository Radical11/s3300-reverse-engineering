"""Install pinned SDK compiler dependencies only in the user's tools cache.

The pinned PyPI Zig distribution contains Clang/LLD. SHA-256 verifies package
bytes against release metadata, not build reproducibility or an upstream
provenance attestation. No global Python package, PATH or system setting changes.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import urllib.request
import zipfile

VERSION = "0.13.0"
CACHE = Path.home() / ".cache/s3300-native-analysis/toolchain"
WHEELS = {
    "win32": {
        "filename": "ziglang-0.13.0-py3-none-win_amd64.whl",
        "url": "https://files.pythonhosted.org/packages/e0/0c/66f4710aedf5544e15779ff9c6e770322986e15daf9299b1a4df0be19e09/ziglang-0.13.0-py3-none-win_amd64.whl",
        "sha256": "b64b2aa936ebbfeecfbb2611df331a5474edebe1246b98c2f56d6ae4d58b71fc",
    },
    "linux": {
        "filename": "ziglang-0.13.0-py3-none-manylinux_2_12_x86_64.manylinux2010_x86_64.musllinux_1_1_x86_64.whl",
        "url": "https://files.pythonhosted.org/packages/0c/b7/ecfdce6368cc3664d301f7f52db4fe1004aa7da7a12c4a9bf1de534ff6ab/ziglang-0.13.0-py3-none-manylinux_2_12_x86_64.manylinux2010_x86_64.musllinux_1_1_x86_64.whl",
        "sha256": "3ce0c9f16547e5d61b32e0d226926e9a2552ef4b91fccf7ab5ea1a623a77824b",
    },
}
EMULATOR_VERSION = "2.1.4"
EMULATOR_WHEELS = {
    "win32": {
        "filename": "unicorn-2.1.4-cp37-abi3-win_amd64.whl",
        "url": "https://files.pythonhosted.org/packages/70/3d/de7be9bd1addabe6d8a1369381f8a080400c349850e978689c5e18287957/unicorn-2.1.4-cp37-abi3-win_amd64.whl",
        "sha256": "d7107500c64ce5c168fbff6bef9485b5db1350050036f4cea568650cf8bdbdf5",
    },
    "linux": {
        "filename": "unicorn-2.1.4-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "url": "https://files.pythonhosted.org/packages/e7/df/ded5e3684c2d7600b30cc8a7530277b8cb36644a1a9d34cade7ebb45604c/unicorn-2.1.4-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "sha256": "9d6e6dea140560de4ebd8446661f7ef84a357d428c14a3ef09dacd306ec8c239",
    },
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def host_key():
    import sys
    key = sys.platform
    if key not in WHEELS or platform.machine().lower() not in ("amd64", "x86_64"):
        raise ValueError("Pinned SDK compiler supports Windows/Linux x86-64 hosts")
    return key


def executable(cache=CACHE):
    return Path(cache) / f"ziglang-{VERSION}" / "ziglang" / ("zig.exe" if host_key() == "win32" else "zig")


def install(cache=CACHE):
    key = host_key()
    record = WHEELS[key]
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / record["filename"]
    if not archive.exists():
        partial = archive.with_suffix(archive.suffix + ".partial")
        if partial.exists():
            raise FileExistsError(f"Incomplete download retained at {partial}; inspect it before retrying")
        with urllib.request.urlopen(record["url"], timeout=60) as response, partial.open("xb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        if sha(partial.read_bytes()) != record["sha256"]:
            raise ValueError("Downloaded compiler wheel hash differs; partial retained")
        partial.rename(archive)
    if sha(archive.read_bytes()) != record["sha256"]:
        raise ValueError("Cached compiler wheel hash differs")
    installation = cache / f"ziglang-{VERSION}"
    target = executable(cache)
    if not installation.exists():
        with zipfile.ZipFile(archive) as wheel:
            for name in wheel.namelist():
                relative = PurePosixPath(name)
                if relative.is_absolute() or ".." in relative.parts or "\\" in name:
                    raise ValueError("Unsafe wheel member path")
                resolved = (installation / Path(*relative.parts)).resolve()
                if not resolved.is_relative_to(installation.resolve()):
                    raise ValueError("Compiler wheel member escapes installation")
            installation.mkdir()
            wheel.extractall(installation)
    # Reauthenticate every shipped file before reusing a potentially partial or
    # modified cache. Extra host-generated cache files are not executed by us.
    with zipfile.ZipFile(archive) as wheel:
        for item in wheel.infolist():
            if item.is_dir():
                continue
            member = installation / Path(*PurePosixPath(item.filename).parts)
            if not member.is_file() or sha(member.read_bytes()) != sha(wheel.read(item)):
                raise ValueError(f"Compiler cache member missing or changed: {item.filename}")
    if key == "linux":
        target.chmod(target.stat().st_mode | 0o100)
    provenance = {"package": "ziglang", "version": VERSION, "host": key,
                  "url": record["url"], "wheel_sha256": record["sha256"],
                  "executable_sha256": sha(target.read_bytes()),
                  "all_wheel_members_verified": True, "global_settings_changed": False}
    (cache / "sdk-toolchain-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    return provenance


def emulator_directory(cache=CACHE):
    return Path(cache) / f"unicorn-{EMULATOR_VERSION}"


def install_emulator(cache=CACHE):
    key = host_key()
    record = EMULATOR_WHEELS[key]
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / record["filename"]
    if not archive.exists():
        partial = archive.with_suffix(archive.suffix + ".partial")
        with urllib.request.urlopen(record["url"], timeout=60) as response, partial.open("xb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        if sha(partial.read_bytes()) != record["sha256"]:
            raise ValueError("Downloaded emulator hash differs; partial retained")
        partial.rename(archive)
    if sha(archive.read_bytes()) != record["sha256"]:
        raise ValueError("Cached emulator hash differs")
    destination = emulator_directory(cache)
    with zipfile.ZipFile(archive) as wheel:
        for item in wheel.infolist():
            relative = PurePosixPath(item.filename)
            if relative.is_absolute() or ".." in relative.parts or "\\" in item.filename:
                raise ValueError("Unsafe emulator member")
            if not (destination / Path(*relative.parts)).resolve().is_relative_to(destination.resolve()):
                raise ValueError("Emulator path escape")
        if not destination.exists():
            destination.mkdir()
            wheel.extractall(destination)
        for item in wheel.infolist():
            if item.is_dir():
                continue
            member = destination / Path(*PurePosixPath(item.filename).parts)
            if not member.is_file() or sha(member.read_bytes()) != sha(wheel.read(item)):
                raise ValueError(f"Emulator cache missing/changed: {item.filename}")
    provenance = {"package": "unicorn", "version": EMULATOR_VERSION, "host": key,
                  "url": record["url"], "wheel_sha256": record["sha256"],
                  "all_wheel_members_verified": True, "global_settings_changed": False}
    (cache / "sdk-emulator-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    return provenance


if __name__ == "__main__":
    print(json.dumps(install(), indent=2))
