"""Generate compact creative-look tables and compile a HOST test library.

The production C module is portable integer-only RGB8 code. Native builds
validate the module; they do not install it or establish the camera buffer ABI.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT/"firmware/looks"


def load_profiles(path=DIRECTORY/"profiles.json"):
    config = json.loads(path.read_text())
    x, looks = config["anchors_x"], config["looks"]
    if len(x) != 7 or x[0] != 0 or x[-1] != 255 or any(type(v) is not int for v in x) or any(a >= b for a, b in zip(x, x[1:])):
        raise ValueError("Invalid shared tone anchors")
    if [p["id"] for p in looks] != [1, 2, 3, 4]:
        raise ValueError("Expected the four fixed look IDs")
    for profile in looks:
        y, gain, offset = profile["tone"], profile["gain_q8"], profile["offset"]
        if len(y) != 7 or any(type(v) is not int or not 0 <= v <= 255 for v in y) or any(a > b for a, b in zip(y, y[1:])):
            raise ValueError("Tone must be monotonic RGB8 anchors")
        if len(gain) != 3 or any(type(v) is not int or not 0 <= v <= 512 for v in gain):
            raise ValueError("Gain outside bounded Q8 range")
        if len(offset) != 3 or any(type(v) is not int or not -127 <= v <= 127 for v in offset):
            raise ValueError("Offset outside signed byte range")
    if looks[3]["gain_q8"] != [256]*3 or looks[3]["offset"] != [0]*3:
        raise ValueError("Mono profile must remain neutral")
    return config


def evaluate(config, look, channel, value):
    if look == 0:
        return value
    profile, x = config["looks"][look-1], config["anchors_x"]
    i = next(i for i in range(6) if value <= x[i+1])
    width = x[i+1]-x[i]
    y = profile["tone"]
    tone = y[i]+((value-x[i])*(y[i+1]-y[i])+width//2)//width
    return max(0, min(255, ((tone*profile["gain_q8"][channel]+128) >> 8)+profile["offset"][channel]))


def reference(config, data, look):
    if look not in range(5) or len(data)%3:
        raise ValueError("Invalid RGB8/reference arguments")
    if look == 0:
        return bytes(data)
    result = bytearray()
    for i in range(0, len(data), 3):
        if look == 4:
            y = (77*data[i]+150*data[i+1]+29*data[i+2]+128) >> 8
            result.extend([evaluate(config, look, 0, y)]*3)
        else:
            result.extend(evaluate(config, look, c, data[i+c]) for c in range(3))
    return bytes(result)


def generated_header(config):
    def vector(values):
        return "{ "+", ".join(str(v) for v in values)+" }"
    def table(values):
        return "{\n"+"\n".join("    "+", ".join(str(v) for v in values[i:i+16])+"," for i in range(0, 256, 16))+"\n}"
    rows = ["/* Generated from profiles.json by tools/build_creative_looks.py. */",
            "#ifndef S3300_LOOK_TABLES_H", "#define S3300_LOOK_TABLES_H",
            "/* 3*3*256 + 256 = 2560 read-only bytes; no frame allocation. */",
            "static const uint8_t s3300_colour_tables[3][3][256] = {"]
    for look in range(1, 4):
        rows.append("{")
        rows.extend(table([evaluate(config, look, c, value) for value in range(256)])+"," for c in range(3))
        rows.append("},")
    rows += ["};", "static const uint8_t s3300_mono_table[256] = "+table([evaluate(config, 4, 0, value) for value in range(256)])+";",
             "#ifdef S3300_LOOKS_REFERENCE", "struct s3300_reference_profile { int tone[7]; int gain[3]; int offset[3]; };",
             "static const unsigned s3300_reference_x[7] = "+vector(config["anchors_x"])+";",
             "static const struct s3300_reference_profile s3300_reference_profiles[4] = {"]
    rows += ["{ "+", ".join(vector(p[k]) for k in ("tone", "gain_q8", "offset"))+" }," for p in config["looks"]]
    rows += ["};", "#endif", "#endif", ""]
    return "\n".join(rows)


def compile_native(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    library = output/("creative_looks.dll" if os.name == "nt" else "libcreative_looks.so")
    if library.exists():
        raise ValueError("Native output exists")
    if (DIRECTORY/"look_tables.h").read_text() != generated_header(load_profiles()):
        raise ValueError("Generated header is stale")
    source = str(DIRECTORY/"looks.c")
    if os.name == "nt":
        vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)"))/"Microsoft Visual Studio/Installer/vswhere.exe"
        installation = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip()
        if not installation:
            raise RuntimeError("MSVC build tools unavailable")
        developer = Path(installation)/"Common7/Tools/VsDevCmd.bat"
        for path in (str(developer), str(library), source):
            if any(c in path for c in '\r\n"%!&|<>'):
                raise ValueError("Unsafe command-script path")
        command = 'cl.exe /nologo /O2 /W4 /WX /LD /DS3300_LOOKS_NATIVE_TEST /DS3300_LOOKS_REFERENCE "'+source+'" /link /OUT:"'+str(library)+'"'
        batch = output/"build.cmd"
        batch.write_text('@echo off\ncall "'+str(developer)+'" -no_logo -arch=x64\nif errorlevel 1 exit /b 1\n'+command+'\nexit /b %errorlevel%\n')
        run = subprocess.run(["cmd.exe", "/d", "/c", str(batch)], cwd=output, capture_output=True, text=True)
        compiler = "MSVC /O2 /W4 /WX"
    else:
        cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not cc:
            raise RuntimeError("Host C compiler unavailable")
        run = subprocess.run([cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", "-DS3300_LOOKS_REFERENCE", source, "-o", str(library)], capture_output=True, text=True)
        compiler = Path(cc).name+" -O2 -Wall -Wextra -Werror"
    if run.returncode:
        raise RuntimeError("Native build failed: "+run.stdout+run.stderr)
    return library, compiler


def load_native(path):
    library = ctypes.CDLL(str(path))
    for name in ("s3300_look_row", "s3300_look_reference_row"):
        function = getattr(library, name)
        function.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_uint]
        function.restype = ctypes.c_int
    return library


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--native", type=Path, help="Build a host library in a new output directory")
    args = parser.parse_args()
    if args.generate:
        (DIRECTORY/"look_tables.h").write_text(generated_header(load_profiles()))
    if args.native:
        path, compiler = compile_native(args.native)
        print(json.dumps({"host_library": str(path), "compiler": compiler, "table_bytes": 2560,
                          "camera_integrated": False}))


if __name__ == "__main__":
    main()
