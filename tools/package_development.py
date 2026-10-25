"""Reproducible source-only development package; never includes vendor inputs."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[1]
ROOT_FILES=("README.md","CONTRIBUTING.md","PROGRESS.md","LICENSE","THIRD_PARTY.md","requirements-analysis.txt","s3300.py",".gitignore")
SAFE_ROOTS=("tools","tests","docs/development","firmware/sdk","firmware/looks","firmware/branding","hardware",".github/workflows")
SUFFIXES={".py",".ps1",".java",".md",".json",".txt",".c",".h",".ld",".svg",".jpg",".yml",".yaml",".html",".css",".js"}


def source_files(root=ROOT):
    files={root/name for name in ROOT_FILES if (root/name).is_file()}
    for relative in SAFE_ROOTS:
        for path in (root/relative).rglob("*"):
            if not path.is_file():continue
            parts=path.relative_to(root).parts
            if "vendor" in parts or "__pycache__" in parts or path.suffix.lower() not in SUFFIXES:continue
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("Source package cannot follow external links")
            files.add(path)
    # Metadata/evidence and notes are required by tests and reproducible mapping.
    # No generated listings, raw binaries, personal photo manifests or WPD IDs.
    for folder in ("notes","evidence"):
        for path in (root/folder).rglob("*"):
            if not path.is_file() or path.suffix.lower() not in ({".md"} if folder=="notes" else {".json"}):continue
            if folder=="evidence" and any(t in path.name for t in ("camera-samples","camera-post-copy","wpd-device-info","ptp-reflash-all-objects")):continue
            files.add(path)
    if any(path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) for path in files):
        raise ValueError("Source package cannot include external links")
    return sorted(files,key=lambda path:path.relative_to(root).as_posix())


def build(output,root=ROOT):
    output=Path(output).resolve()
    if output.exists() or not output.is_relative_to((root/"derived").resolve()):
        raise ValueError("Choose a new local .zip under derived/")
    files=source_files(root)
    records=[]
    for path in files:
        name=path.relative_to(root).as_posix()
        if name.startswith(("sources/","derived/","samples/","work/","experiments/","tools/vendor/")):
            raise ValueError("Private/vendor path selected")
        body=path.read_bytes();records.append((name,body))
    metadata={"schema_version":1,"source_only":True,"vendor_inputs_included":False,
        "files":[{"path":name,"bytes":len(body),"sha256":hashlib.sha256(body).hexdigest()} for name,body in records]}
    records.append(("SOURCE-PACKAGE-MANIFEST.json",(json.dumps(metadata,indent=2)+"\n").encode()))
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("xb") as stream,zipfile.ZipFile(stream,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for name,body in records:
            info=zipfile.ZipInfo(name,date_time=(2026,10,24,0,0,0));info.external_attr=0o100644<<16
            archive.writestr(info,body,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
    return {"path":str(output),"files":len(records),"sha256":hashlib.sha256(output.read_bytes()).hexdigest(),
            "vendor_inputs_included":False,"remote_publication":False}
