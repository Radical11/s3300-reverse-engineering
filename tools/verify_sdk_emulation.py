"""Run our compiled MIPS SDK under a bounded host emulator, not on a camera."""
from io import BytesIO
import json
from pathlib import Path
import random
import struct
import sys

from elftools.elf.elffile import ELFFile
from setup_sdk_toolchain import EMULATOR_VERSION, emulator_directory

ROOT = Path(__file__).resolve().parents[1]
STACK = 0x200000
RETURN = 0x300000
DATA = 0x400000


def emulator_imports():
    directory = emulator_directory()
    if not (directory / "unicorn/__init__.py").is_file():
        raise ImportError("Pinned SDK emulator missing; use build_sdk.py --install-toolchain")
    sys.path.insert(0, str(directory))
    import unicorn
    if unicorn.__version__ != EMULATOR_VERSION:
        raise ValueError("SDK emulator version differs from the pinned profile")
    if not Path(unicorn.__file__).resolve().is_relative_to(directory.resolve()):
        raise ValueError("SDK emulator was imported from outside the pinned tools cache")
    return unicorn


class Machine:
    """No firmware, syscalls, MMIO or camera timing model is loaded."""
    def __init__(self, module):
        uc = emulator_imports()
        from unicorn import mips_const as registers
        self.api, self.registers = uc, registers
        self.engine = uc.Uc(uc.UC_ARCH_MIPS, uc.UC_MODE_MIPS32 | uc.UC_MODE_LITTLE_ENDIAN)
        elf = ELFFile(BytesIO(module))
        pages = set()
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD" or not segment["p_memsz"]:
                continue
            start = segment["p_vaddr"] & ~4095
            end = (segment["p_vaddr"] + segment["p_memsz"] + 4095) & ~4095
            pages.update(range(start, end, 4096))
        for page in sorted(pages):
            self.engine.mem_map(page, 4096)
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD" and segment["p_filesz"]:
                self.engine.mem_write(segment["p_vaddr"], segment.data())
        self.engine.mem_map(STACK, 0x10000)
        self.engine.mem_map(RETURN, 4096)
        self.engine.mem_write(RETURN, bytes(8))
        self.engine.mem_map(DATA, 0x10000)
        self.functions = {s.name: s["st_value"] for s in elf.get_section_by_name(".symtab").iter_symbols()
                          if s["st_info"]["type"] == "STT_FUNC"}
        self.allowed_writes = []
        self.invalid_write = None
        self.engine.hook_add(uc.UC_HOOK_MEM_WRITE, self._write)

    def _write(self, engine, access, address, size, value, user):
        if STACK <= address and address + size <= STACK + 0x10000:
            return
        if not any(start <= address and address + size <= end for start, end in self.allowed_writes):
            self.invalid_write = (address, size)
            engine.emu_stop()

    def call(self, name, arguments, allowed_writes=()):
        r = self.registers
        engine = self.engine
        self.allowed_writes = list(allowed_writes)
        self.invalid_write = None
        saved = [getattr(r, f"UC_MIPS_REG_S{i}") for i in range(8)] + [r.UC_MIPS_REG_FP, r.UC_MIPS_REG_GP]
        expected = {}
        for index, register in enumerate(saved):
            expected[register] = 0x11110000 + index * 0x101
            engine.reg_write(register, expected[register])
        initial_sp = STACK + 0xff00
        engine.reg_write(r.UC_MIPS_REG_SP, initial_sp)
        engine.reg_write(r.UC_MIPS_REG_RA, RETURN)
        for index in range(4):
            engine.reg_write(getattr(r, f"UC_MIPS_REG_A{index}"), arguments[index] if index < len(arguments) else 0)
        engine.emu_start(self.functions[name], RETURN, timeout=2_000_000, count=2_000_000)
        if self.invalid_write:
            raise ValueError(f"MIPS SDK wrote outside declared output/stack: {self.invalid_write}")
        if engine.reg_read(r.UC_MIPS_REG_PC) != RETURN:
            raise ValueError("MIPS SDK did not reach its expected return within the budget")
        if engine.reg_read(r.UC_MIPS_REG_SP) != initial_sp:
            raise ValueError("MIPS SDK did not preserve its stack pointer")
        for register, value in expected.items():
            if engine.reg_read(register) != value:
                raise ValueError("MIPS SDK corrupted a callee-saved register")
        return engine.reg_read(r.UC_MIPS_REG_V0)


def verify(path):
    from build_sdk import inspect_module
    from build_creative_looks import load_profiles, reference
    module = Path(path).read_bytes()
    inspect_module(module)
    machine = Machine(module)
    config = load_profiles()
    rng = random.Random(3300)
    rows = [b"", bytes(range(255)), bytes(rng.randrange(256) for _ in range(3 * 257)),
            bytes(channel for value in range(256) for channel in (value, value, value))]
    checks = 0
    for data in rows:
        for look in range(5):
            input_address = DATA + 16
            machine.engine.mem_write(DATA, b"L" * 16 + data + b"R" * 16)
            result = machine.call("s3300_look_row", [input_address, len(data) // 3, look],
                                  [(input_address, input_address + len(data))])
            output = bytes(machine.engine.mem_read(input_address, len(data))) if data else b""
            if result != 1 or output != reference(config, data, look):
                raise ValueError("Compiled MIPS look differs from independent Python reference")
            if bytes(machine.engine.mem_read(DATA, 16)) != b"L" * 16 or bytes(machine.engine.mem_read(input_address + len(data), 16)) != b"R" * 16:
                raise ValueError("Compiled MIPS look changed row guards")
            checks += 1
    for arguments in ([0, 1, 1], [DATA + 16, 1, 99], [DATA + 16, 0xffffffff, 1]):
        if machine.call("s3300_look_row", arguments) != 0:
            raise ValueError("Compiled MIPS look failed invalid-argument rejection")
        checks += 1
    if machine.call("s3300_look_row", [0, 0, 0]) != 1:
        raise ValueError("Original empty NULL row did not bypass")
    checks += 1
    for context in (0, 0x3f, 0x40, 0x41, 0x50, 0x90, 0xa0, 0xb0, 0xffffffff):
        expected = {0x40: 0, 0x50: 1, 0xa0: 2, 0xb0: 5}.get(context, 8)
        if machine.call("s3300_command_context_index", [context]) != expected:
            raise ValueError("Compiled MIPS context lookup differs")
        checks += 1
    for value in (0, 49, 50, 99, 100, 199, 200, 999, 1000, 0xffffffff):
        category, base = next((category, base) for limit, category, base in (
            (50, 0, 0), (100, 3, 50), (200, 1, 100), (1000, 4, 200), (0x100000000, 2, 1000)) if value < limit)
        machine.engine.mem_write(DATA, bytes(8))
        if machine.call("s3300_command_id_parts", [value, DATA, DATA + 4], [(DATA, DATA + 8)]) != 1:
            raise ValueError("Compiled MIPS command categorization failed")
        if struct.unpack("<II", machine.engine.mem_read(DATA, 8)) != (category, value - base):
            raise ValueError("Compiled MIPS command categorization differs")
        checks += 1
    for arguments in ([15, 0, DATA + 4], [15, DATA, 0]):
        if machine.call("s3300_command_id_parts", arguments) != 0:
            raise ValueError("Compiled MIPS categorization accepted NULL output")
        checks += 1
    counters = bytes(rng.randrange(256) for _ in range(24))
    machine.engine.mem_write(DATA, counters)
    machine.engine.mem_write(DATA + 0x100, b"X" * 24)
    if machine.call("s3300_counter_decode", [DATA, 24, DATA + 0x100], [(DATA + 0x100, DATA + 0x118)]) != 1:
        raise ValueError("Compiled MIPS counter decoder failed")
    if bytes(machine.engine.mem_read(DATA + 0x100, 24)) != counters:
        raise ValueError("Compiled MIPS counter decoder field order differs")
    checks += 1
    for arguments in ([0, 24, DATA + 0x100], [DATA, 23, DATA + 0x100], [DATA, 24, 0]):
        if machine.call("s3300_counter_decode", arguments) != 0:
            raise ValueError("Compiled MIPS decoder accepted invalid arguments")
        checks += 1
    stores = [bytes(0x1a0), bytes([255]) * 0x1a0, bytes(rng.randrange(256) for _ in range(0x1a0))]
    for store in stores:
        expected = sum(store[:0x19e]) & 255
        machine.engine.mem_write(DATA, store)
        if machine.call("s3300_settings_checksum", [DATA, len(store), DATA + 0x1000], [(DATA + 0x1000, DATA + 0x1001)]) != 1:
            raise ValueError("Compiled MIPS settings checksum failed")
        if bytes(machine.engine.mem_read(DATA + 0x1000, 1)) != bytes([expected]):
            raise ValueError("Compiled MIPS settings checksum differs")
        # Last two store bytes must not affect the checksum.
        altered = bytearray(store)
        altered[-2:] = bytes([store[-2] ^ 255, store[-1] ^ 255])
        machine.engine.mem_write(DATA, bytes(altered))
        machine.call("s3300_settings_checksum", [DATA, len(store), DATA + 0x1000], [(DATA + 0x1000, DATA + 0x1001)])
        if bytes(machine.engine.mem_read(DATA + 0x1000, 1)) != bytes([expected]):
            raise ValueError("Excluded trailer bytes affected settings checksum")
        checks += 2
    for arguments in ([0, 0x1a0, DATA + 0x1000], [DATA, 0x19f, DATA + 0x1000], [DATA, 0x1a0, 0]):
        if machine.call("s3300_settings_checksum", arguments) != 0:
            raise ValueError("Compiled MIPS checksum accepted invalid arguments")
        checks += 1
    return {"performed": True, "engine": "Unicorn", "version": EMULATOR_VERSION,
            "reference_cases_passed": checks, "callee_saved_registers_preserved": True,
            "stack_pointer_preserved": True, "writes_bounded_to_outputs_and_stack": True,
            "original_bypass_verified": True, "camera_executed": False,
            "scope": "Our compiled SDK on synthetic memory only; no camera peripherals/cache/DMA/real-time model"}


if __name__ == "__main__":
    print(json.dumps(verify(Path(sys.argv[1])), indent=2))
