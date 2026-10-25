"""Build and independently inspect a freestanding, analysis-only MIPS SDK.

The linked module uses a synthetic address. It is never a firmware candidate,
hook, camera API registration, staging payload or recovery demonstration.
"""
import argparse
from io import BytesIO
import json
from pathlib import Path
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from setup_sdk_toolchain import (VERSION, executable,
                                 emulator_directory, install, install_emulator, sha)

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = "2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b"
REQUIRED_SYMBOLS = ("s3300_look_row", "s3300_counter_decode",
                    "s3300_command_context_index", "s3300_command_id_parts",
                    "s3300_settings_checksum")
FLAGS = ["-target", "mipsel-freestanding", "-mcpu=mips32r2", "-mabi=32",
         "-msoft-float", "-fno-pic", "-ffreestanding", "-fno-builtin",
         "-fno-stack-protector", "-fno-ident", "-Os", "-Wall", "-Wextra", "-Werror"]
SOURCES = ("firmware/looks/looks.c", "firmware/looks/looks.h", "firmware/looks/look_tables.h",
           "firmware/looks/profiles.json", "firmware/sdk/contracts.c", "firmware/sdk/contracts.h",
           "firmware/sdk/analysis-only.ld")
BUILD_TOOLS = ("tools/build_sdk.py", "tools/setup_sdk_toolchain.py", "tools/verify_sdk_emulation.py")


def check_toolchain():
    compiler = executable()
    result = {"compiler": str(compiler), "compiler_present": compiler.is_file(),
              "expected_version": VERSION, "emulator_present": (emulator_directory() / "unicorn/__init__.py").is_file(),
              "global_settings_changed": False}
    if compiler.is_file():
        process = subprocess.run([str(compiler), "version"], capture_output=True, text=True, check=True)
        result["version"] = process.stdout.strip()
        result["compiler_sha256"] = sha(compiler.read_bytes())
    result["ready"] = result.get("version") == VERSION and result["emulator_present"]
    return result


def inspect_module(data, *, require_symbols=True):
    """Validate independently from the compiler/linker's success status."""
    elf = ELFFile(BytesIO(data))
    if elf.elfclass != 32 or not elf.little_endian or elf.header["e_machine"] != "EM_MIPS":
        raise ValueError("SDK output must be little-endian ELF32 MIPS")
    if elf.header["e_type"] not in ("ET_REL", "ET_EXEC"):
        raise ValueError("SDK output must be a relocatable object or static executable")
    flags = elf.header["e_flags"]
    if flags & 0xf0000000 != 0x70000000 or flags & 0xf000 != 0x1000:
        raise ValueError("SDK output must declare MIPS32r2 and o32")
    if flags & 0x0fff0a20:
        raise ValueError("SDK output declares unsupported MIPS ISA/ABI features")
    abi_section = elf.get_section_by_name(".MIPS.abiflags")
    if abi_section is None or len(abi_section.data()) != 24:
        raise ValueError("Compiled SDK output is missing its ABI declaration")
    abi = struct.unpack("<HBBBBBBIIII", abi_section.data())
    if abi[:7] != (0, 32, 2, 1, 0, 0, 3) or abi[7] or abi[8] or abi[9] & ~1 or abi[10]:
        raise ValueError("SDK output must declare standard 32-bit integer-only soft-float ABI")
    if any(section["sh_type"] == "SHT_DYNAMIC" for section in elf.iter_sections()):
        raise ValueError("SDK output unexpectedly requires a dynamic loader")
    if any(segment["p_type"] == "PT_INTERP" for segment in elf.iter_segments()):
        raise ValueError("SDK output unexpectedly has an interpreter")
    symbols_section = elf.get_section_by_name(".symtab")
    if symbols_section is None:
        raise ValueError("Retain SDK symbols for independent import checks")
    symbols, undefined = {}, []
    for symbol in symbols_section.iter_symbols():
        if symbol.name and symbol["st_shndx"] == "SHN_UNDEF":
            undefined.append(symbol.name)
        if symbol.name and symbol["st_info"]["type"] == "STT_FUNC" and symbol["st_shndx"] != "SHN_UNDEF":
            symbols[symbol.name] = {"address": symbol["st_value"], "bytes": symbol["st_size"]}
    if undefined:
        raise ValueError("SDK output contains undefined imports: " + ", ".join(undefined))
    if require_symbols and not set(REQUIRED_SYMBOLS).issubset(symbols):
        raise ValueError("SDK output is missing required exported functions")
    relocations = []
    for section in elf.iter_sections():
        if section["sh_type"] in ("SHT_REL", "SHT_RELA"):
            relocations.append({"section": section.name, "count": section.num_relocations()})
    if elf.header["e_type"] == "ET_EXEC" and any(record["count"] for record in relocations):
        raise ValueError("Linked SDK output still contains unresolved relocations")
    sys.path.insert(0, str(ROOT / "tools/vendor"))
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    executable_sections, assembly = [], []
    for section in elf.iter_sections():
        if not section["sh_flags"] & 4 or not section["sh_size"]:
            continue
        body = section.data()
        instructions = list(decoder.disasm_lite(body, section["sh_addr"]))
        if sum(item[1] for item in instructions) != len(body):
            raise ValueError("SDK executable section did not fully decode as MIPS32")
        for offset in range(0, len(body), 4):
            word = struct.unpack_from("<I", body, offset)[0]
            if word >> 26 in (16, 17, 18, 49, 50, 53, 54, 57, 58, 61, 62):
                raise ValueError("SDK unexpectedly uses coprocessor/FP instructions")
        if any("$gp" in operands for _, _, _, operands in instructions):
            raise ValueError("SDK unexpectedly depends on a runtime global pointer")
        executable_sections.append({"name": section.name, "address": section["sh_addr"],
                                    "bytes": len(body), "instructions": len(instructions),
                                    "sha256": sha(body)})
        assembly.extend(f"{pc:08x} {mnemonic:10} {operands}" for pc, _, mnemonic, operands in instructions)
    if not executable_sections:
        raise ValueError("SDK has no executable instructions")
    if elf.header["e_type"] == "ET_EXEC":
        if elf.header["e_entry"] != symbols.get("s3300_look_row", {}).get("address"):
            raise ValueError("Analysis-only entry must be s3300_look_row")
        for section in elf.iter_sections():
            if section["sh_flags"] & 2 and section["sh_size"]:
                if section["sh_addr"] < 0x10000 or section["sh_addr"] + section["sh_size"] > 0x40000:
                    raise ValueError("SDK escaped its synthetic verification address space")
    return {"elf_type": elf.header["e_type"], "flags_hex": hex(flags), "byte_order": "little",
            "isa": "MIPS32r2", "abi": "o32", "fp_abi": "soft-float (generated SDK declaration only)",
            "symbols": symbols, "undefined_imports": undefined, "relocations": relocations,
            "executable_sections": executable_sections, "full_linear_decode": True,
            "coprocessor_instructions": False, "runtime_gp_dependency": False}, "\n".join(assembly) + "\n"


def baseline_declaration(root=ROOT):
    source = root / "sources/extracted-v1.1/S3300Update/firmware/firmware.bin"
    if not source.is_file():
        return {"verified": False, "reason": "Vendor source deliberately not distributed"}
    raw = source.read_bytes()
    if sha(raw) != SOURCE_SHA:
        raise ValueError("Original vendor firmware hash differs")
    elf = ELFFile(BytesIO(raw[0x1026c0:]))
    flags = elf.header["e_flags"]
    if not elf.little_endian or elf.elfclass != 32 or flags != 0x70001001:
        raise ValueError("Vendor application architecture metadata differs")
    return {"verified": True, "source_sha256": SOURCE_SHA, "application_carrier_offset": 0x1026c0,
            "flags_hex": hex(flags), "elf_class": 32, "byte_order": "little",
            "isa_declaration": "MIPS32r2", "abi_declaration": "o32",
            "floating_point_abi": "unknown; original does not contain .MIPS.abiflags",
            "vendor_headers_modified": False,
            "runtime_calling_convention_fully_verified": False}


def compile_pass(compiler, destination, root=ROOT):
    destination.mkdir()
    commands, logs, objects = [], [], []
    canonical = [f"-ffile-prefix-map={root}=.", f"-fdebug-prefix-map={root}=."]
    for relative, name in (("firmware/looks/looks.c", "looks.o"), ("firmware/sdk/contracts.c", "contracts.o")):
        output = destination / name
        command = [str(compiler), "cc", *FLAGS, *canonical, "-c", str(root / relative), "-o", str(output)]
        result = subprocess.run(command, cwd=root, capture_output=True, text=True, check=True)
        inspect_module(output.read_bytes(), require_symbols=False)
        objects.append(output)
        commands.append(command)
        logs.append(result.stdout + result.stderr)
    module = destination / "sdk-analysis-only.elf"
    command = [str(compiler), "cc", *FLAGS, "-nostdlib", "-static", "-g", "-Wl,--build-id=none",
               "-Wl,-e,s3300_look_row", "-Wl,--no-gc-sections",
               "-T", str(root / "firmware/sdk/analysis-only.ld"), *map(str, objects), "-o", str(module)]
    result = subprocess.run(command, cwd=root, capture_output=True, text=True, check=True)
    commands.append(command)
    logs.append(result.stdout + result.stderr)
    return module, objects, commands, logs


def build(output, *, emulate=True):
    output = Path(output).resolve()
    if not output.is_relative_to((ROOT / "derived").resolve()) or output.exists():
        raise ValueError("SDK output must be a new directory under derived/")
    toolchain = check_toolchain()
    if toolchain.get("version") != VERSION:
        raise ValueError("Pinned compiler unavailable; use --install-toolchain first")
    if emulate and not toolchain["emulator_present"]:
        raise ValueError("Pinned emulator unavailable; use --install-toolchain first")
    from build_creative_looks import generated_header, load_profiles
    if (ROOT / "firmware/looks/look_tables.h").read_text() != generated_header(load_profiles()):
        raise ValueError("Creative-look tables are stale; regenerate them explicitly")
    baseline = baseline_declaration()
    source_hashes = {name: sha((ROOT / name).read_bytes()) for name in SOURCES}
    output.mkdir(parents=True)
    passes = [compile_pass(executable(), output / name) for name in ("pass1", "pass2")]
    first, objects, commands, logs = passes[0]
    second = passes[1][0]
    if first.read_bytes() != second.read_bytes():
        raise ValueError("Two independent SDK links are not byte-identical")
    for left, right in zip(objects, passes[1][1]):
        if left.read_bytes() != right.read_bytes():
            raise ValueError("Two independent SDK object builds differ")
    inspection, assembly = inspect_module(first.read_bytes())
    target = output / "sdk-analysis-only.elf"
    target.write_bytes(first.read_bytes())
    (output / "sdk-analysis-only.asm").write_text(assembly, encoding="utf-8")
    execution = {"performed": False, "reason": "Explicitly disabled"}
    if emulate:
        from verify_sdk_emulation import verify
        execution = verify(target)
    if any(sha((ROOT / name).read_bytes()) != digest for name, digest in source_hashes.items()):
        raise ValueError("SDK source changed during the build")
    report = {"schema_version": 1, "artifact": "sdk-analysis-only.elf", "artifact_sha256": sha(target.read_bytes()),
              "source_hashes": source_hashes,
              "build_tools_hashes": {name: sha((ROOT / name).read_bytes()) for name in BUILD_TOOLS},
              "toolchain": toolchain, "compiler_commands": commands + passes[1][2],
              "compiler_logs": logs + passes[1][3], "target": inspection,
              "vendor_architecture_declaration": baseline, "two_builds_byte_identical": True,
              "objects": [{"name": item.name, "sha256": sha(item.read_bytes()), "inspection": inspect_module(item.read_bytes(), require_symbols=False)[0]} for item in objects],
              "emulation": execution, "synthetic_link_address": "0x10000; not a recovered camera placement",
              "camera_integrated": False, "camera_executed": False,
              "ready_for_executable_trial": False, "software_recovery_verified": False,
              "blocked_by": ["Verified camera placement/hook and cache maintenance", "Complete saved-photo buffer ABI/ownership", "Demonstrated software recovery"],
              "limitations": ["Generated soft-float declaration is a choice for integer-only SDK code, not recovery of vendor floating-point ABI.",
                              "A compiler/host emulator does not model camera MMIO, caches, DMA, interrupts or real performance.",
                              "This ELF is never an update, trial registration or automatic executable patch."]}
    (output / "manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path, help="New local output directory under derived/")
    parser.add_argument("--install-toolchain", action="store_true", help="Install pinned compiler/emulator in the dedicated tools cache")
    parser.add_argument("--check", action="store_true", help="Read-only local compiler/emulator readiness")
    parser.add_argument("--inspect", type=Path, help="Independently inspect an existing compiled SDK ELF")
    args = parser.parse_args(argv)
    try:
        if args.install_toolchain:
            install()
            install_emulator()
        if args.inspect:
            print(json.dumps(inspect_module(args.inspect.read_bytes())[0], indent=2))
        elif args.check:
            report = check_toolchain()
            print(json.dumps(report, indent=2))
            return 0 if report["ready"] else 1
        elif args.output:
            report = build(args.output)
            print(json.dumps({"output": str(args.output), "sha256": report["artifact_sha256"],
                              "two_builds_byte_identical": report["two_builds_byte_identical"],
                              "emulation": report["emulation"], "camera_integrated": False,
                              "ready_for_executable_trial": False}, indent=2))
        elif not args.install_toolchain:
            parser.error("Supply output, --check, --inspect or --install-toolchain")
        return 0
    except (OSError, ValueError, ImportError, subprocess.CalledProcessError) as exc:
        print(f"SDK error: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stdout or "", exc.stderr or "", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
