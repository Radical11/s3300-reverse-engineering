"""Authenticate PTP handler registrations without sending any camera request.

Bounded Unicorn runs original registration and lookup instructions in synthetic
RAM. Allocation, logging and the state-changing 9002 endpoint are host stubs.
This is offline execution of selected instructions, not camera evidence.
"""
import argparse
import json
from pathlib import Path
import struct

from map_development_contracts import (ROOT, WORKSPACE, BASELINE, AddressMap,
    load_analysis, digest, Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN)
from map_recovery_transport import check_dossiers

FUNCTIONS = (0x8057ac40, 0x8057db04, 0x8063b3bc, 0x80634c18,
    0x80779e00, 0x8077f050, 0x8077f108, 0x8077f17c, 0x8077f204,
    0x8077f48c, 0x8077f584, 0x8077d248, 0x8077ccac, 0x8078d544, 0x8078d408)
EXECUTED = (0x8057ac40, 0x8057db04, 0x8077f050, 0x8077f108,
    0x8077f17c, 0x8077f204, 0x8077f48c, 0x8077f584,
    0x8077d248, 0x8077ccac, 0x8078d544, 0x8078d408)
ASSERTIONS = {
    0x8057ad20: ('ori', '$a0, $zero, 0x9002'),
    0x8057ad28: ('jal', '0x8078d544'),
    0x8057ad30: ('ori', '$a0, $zero, 0x9003'),
    0x8057ad38: ('jal', '0x8078d408'),
    0x8077f140: ('sb', '$a3, 3($t0)'),
    0x8077f150: ('sb', '$t5, 2($t3)'),
    0x8077f160: ('sh', '$a0, ($t0)'),
    0x8077f164: ('sw', '$a2, 4($v1)'),
    0x8077f16c: ('sw', '$a1, 8($v1)'),
    0x8077f404: ('sh', '$t7, 0xc0($a3)'),
    0x8077f408: ('sh', '$t6, 0xcc($a3)'),
    0x8077f430: ('sw', '$t2, 0xc8($a3)'),
    0x8077f434: ('sw', '$t1, 0xc4($a3)'),
    0x8077f438: ('sw', '$zero, 0xd0($a3)'),
    0x8077a0a0: ('lbu', '$a1, 3($s5)'),
    0x8077a0ac: ('lbu', '$t1, 2($s5)'),
    0x8077a144: ('jal', '0x8077f050'),
    0x8077a748: ('ori', '$a0, $zero, 0x8800'),
    0x8057db7c: ('jal', '0x8063b3bc'),
}


def parse_registry(body):
    """Decode the exact 256 x 12-byte runtime table, including empty slots."""
    if len(body) != 0xc00:
        raise ValueError('Expected the complete 256-record PTP registry')
    return [dict(zip(('opcode', 'route', 'disabled', 'data_phase', 'handler'),
                     struct.unpack_from('<HBBII', body, slot * 12)), slot=slot)
            for slot in range(256)]


def emulate_registry(mapping, native):
    from verify_sdk_emulation import emulator_imports
    api = emulator_imports()
    from unicorn import mips_const as r
    machine = api.Uc(api.UC_ARCH_MIPS, api.UC_MODE_MIPS32 | api.UC_MODE_LITTLE_ENDIAN)
    machine.ctl_set_cpu_model(r.UC_CPU_MIPS32_24KC)
    pages = set()
    def reserve(address, size):
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            physical = page & 0x1fffffff
            if physical not in pages:
                machine.mem_map(physical, 4096); pages.add(physical)
    def write(address, body): machine.mem_write(address & 0x1fffffff, body)
    def read(address, length): return bytes(machine.mem_read(address & 0x1fffffff, length))
    ranges = []
    for address in EXECUTED:
        dossier = json.loads((native / 'functions' / f'{address:08x}.json').read_text())
        for extent in dossier['ranges']:
            start, end = int(extent['start'], 16), int(extent['end_inclusive'], 16) + 1
            reserve(start, end - start); write(start, mapping.read(start, end - start))
            ranges.append((start, end))
    stubs = (0x80020980, 0x800efc30, 0x80778ae4, 0x8057a944, 0x8063b3bc)
    for address in (*stubs, 0x83000000, 0x80898e7c, 0x8065e66a, 0x8065ebdd,
                    0xb0020454, 0xb0022c70): reserve(address, 4)
    for address in stubs:
        write(address, bytes(8)) # hook stops before a synthetic NOP; caller resumes at saved RA
    reserve(0x81000000, 0x10000); reserve(0x82000000, 0x10000)
    state_calls, allocations = [], []
    pending_return = None
    instruction_count = 0
    recent = []
    registration_calls = []
    def guard_write(engine, access, address, size, value, user):
        virtual = (address & 0x1fffffff) | 0x80000000
        if not any(start <= virtual and virtual + size <= end for start, end in
                   ((0x80898000, 0x80899000), (0x81000000, 0x81010000), (0x82000000, 0x82010000))):
            raise ValueError(f'Native registry wrote outside synthetic mutable state: {virtual:#x}')
    def hook(engine, address, size, user):
        nonlocal pending_return, instruction_count
        instruction_count += 1
        recent.append(address)
        if len(recent) > 20: recent.pop(0)
        args = [engine.reg_read(getattr(r, f'UC_MIPS_REG_A{i}')) for i in range(4)]
        if address in (0x8078d544, 0x8078d408):
            registration_calls.append({'wrapper': address, 'arguments': args +
                [struct.unpack('<I', read(engine.reg_read(r.UC_MIPS_REG_SP) + 16, 4))[0]]})
        if address == 0x80020980:
            if args[1] != 0xc00 or allocations: raise ValueError('Unexpected native allocation')
            result = 0x81000000; allocations.append(args[1])
        elif address == 0x800efc30:
            if args[:3] != [0x81000000, 0, 0xc00]: raise ValueError('Unexpected native memset')
            write(args[0], bytes(args[2])); result = args[0]
        elif address in (0x80778ae4, 0x8057a944): result = 0
        elif address == 0x8063b3bc: state_calls.append(args[0]); result = 0
        elif address == 0x83000000 or any(start <= address < end for start, end in ranges) or any(address == start + 4 for start in stubs): return
        else: raise ValueError(f'Unexpected registry execution at {address:#x}')
        engine.reg_write(r.UC_MIPS_REG_V0, result)
        pending_return = engine.reg_read(r.UC_MIPS_REG_RA)
        engine.emu_stop()
    machine.hook_add(api.UC_HOOK_MEM_WRITE, guard_write)
    machine.hook_add(api.UC_HOOK_CODE, hook)
    def call(address, args):
        nonlocal pending_return
        sp = 0x8200ff00
        machine.reg_write(r.UC_MIPS_REG_SP, sp); machine.reg_write(r.UC_MIPS_REG_RA, 0x83000000)
        for i in range(4): machine.reg_write(getattr(r, f'UC_MIPS_REG_A{i}'), args[i] if i < len(args) else 0)
        for i, arg in enumerate(args[4:]): write(sp + 16 + i * 4, struct.pack('<I', arg))
        next_pc = address
        for _ in range(64):
            pending_return = None
            try:
                # Execute one synthetic NOP after JR's target. Stopping exactly
                # at that target can retain a pending branch across emu_start
                # calls; the next helper then returns before executing its body.
                # Unicorn reports the last executed NOP address as PC here.
                machine.emu_start(next_pc, 0x83000004, timeout=5_000_000, count=500000)
            except api.UcError as error:
                raise ValueError(f'Native PTP emulator failed at PC={machine.reg_read(r.UC_MIPS_REG_PC):#x}; RA={machine.reg_read(r.UC_MIPS_REG_RA):#x}; SP={machine.reg_read(r.UC_MIPS_REG_SP):#x}; saved={read(machine.reg_read(r.UC_MIPS_REG_SP),32).hex()}; resume={next_pc:#x}; recent={[hex(x) for x in recent]}; bytes={read(recent[-1],8).hex()}') from error
            if pending_return is None: break
            next_pc = pending_return
        else: raise ValueError('Registry stub-call budget exhausted')
        if machine.reg_read(r.UC_MIPS_REG_PC) != 0x83000000 or machine.reg_read(r.UC_MIPS_REG_SP) != sp:
            raise ValueError(f'Registry did not return with balanced stack: pc={machine.reg_read(r.UC_MIPS_REG_PC):#x}, sp={machine.reg_read(r.UC_MIPS_REG_SP):#x}, recent={[hex(x)for x in recent]}')
        return machine.reg_read(r.UC_MIPS_REG_V0)
    pristine_pages = {page: bytes(machine.mem_read(page, 4096)) for page in pages}
    try:
        result = call(0x8077f204, [])
        initialization = {'status': 'passed' if result == 1 else 'failed', 'return': result,
                          'instructions_executed': instruction_count}
    except ValueError as error:
        initialization = {'status': 'failed', 'error': 'Full-initializer execution did not return within the bounded emulator harness',
            'underlying_error_type': type(error.__cause__).__name__ if error.__cause__ else type(error).__name__,
            'instructions_executed': instruction_count,
            'last_instruction_address': recent[-1],
            'last_instruction_sha256': digest(mapping.read(recent[-1], 4)),
            'meaning': 'full initializer is not synthetically verified; original code was not patched to bypass failure'}
    # Recreate the engine so a failed attempt cannot leak CPU exception/branch
    # state into the smaller registry-helper tests. All code is original;
    # only allocation/logging/state endpoint addresses contain synthetic NOPs.
    machine = api.Uc(api.UC_ARCH_MIPS, api.UC_MODE_MIPS32 | api.UC_MODE_LITTLE_ENDIAN)
    machine.ctl_set_cpu_model(r.UC_CPU_MIPS32_24KC)
    for page, body in pristine_pages.items():
        machine.mem_map(page, 4096); machine.mem_write(page, body)
    machine.hook_add(api.UC_HOOK_MEM_WRITE, guard_write)
    machine.hook_add(api.UC_HOOK_CODE, hook)
    instruction_count = 0; allocations.clear(); recent.clear(); registration_calls.clear()
    write(0x80898e7c, struct.pack('<I', 0x81000000))
    # These records are supplied by the host from static registration findings.
    # The native insertion helper proves layout/search/width semantics only;
    # this does not prove that the initializer or application registered them.
    seeds = ((0x100c, 0x80781028, 2, 0, 0), (0x100d, 0x807815a0, 0, 0, 0),
             (0x9005, 0x80781028, 2, 0, 0), (0x9006, 0x807815a0, 0, 0, 0),
             (0x9002, 0x8057db04, 1, 0, 0), (0x9003, 0, 0, 0, 1))
    for seed in seeds:
        if call(0x8077f108, list(seed)) != 1:
            raise ValueError('Native helper rejected synthetic seed')
    final = {row['opcode']: row for row in parse_registry(read(0x81000000, 0xc00)) if row['opcode']}
    lookup_cases = []
    for opcode in (0x9002, 0x9003, 0x9005, 0x9006, 0xffff):
        result = call(0x8077f050, [opcode])
        target = 0x81000000 + 12 * final[opcode]['slot'] if opcode in final else 0
        if result != target: raise ValueError('Native lookup disagrees with decoded table')
        lookup_cases.append({'opcode': opcode, 'found': bool(result)})
    handler_cases = []
    handler_verification = {'status': 'passed', 'state_endpoint': 'host stub; no peripheral execution'}
    try:
        for state, parameter, expected_calls in ((0, 1, []), (1, 1, [0]), (0, 2, [1]), (1, 2, []), (0, 3, [])):
            write(0x8065ebdd, bytes([state])); write(0x81001000, struct.pack('<IHHII', 16, 1, 0x9002, 7, parameter))
            write(0x81002000, bytes(16)); state_calls.clear()
            result = call(0x8057db04, [0x81001000, 0, 0, 0x81002000])
            if result != 1 or state_calls != expected_calls or read(0x81002000, 8) != bytes.fromhex('0c00000000000120'):
                raise ValueError('9002 branch/response differs')
            handler_cases.append({'synthetic_state_byte': state, 'parameter': parameter,
                                  'state_endpoint_stub_arguments': list(state_calls)})
    except ValueError as error:
        handler_verification = {'status': 'failed', 'error': str(error),
                                'passed_cases_before_failure': len(handler_cases)}
    # Exercise the bounded final-slot search and full-table rejection in the
    # native insertion helper, with guard bytes immediately outside the table.
    write(0x81000000, struct.pack('<HBBII', 1, 0, 0, 0, 0) * 255 + bytes(12))
    write(0x81000c00, b'PTPguard')
    if call(0x8077f108, [0xabcd, 0x81234560, 2, 0x101, 0x102]) != 1: raise ValueError('Last slot insertion failed')
    last = parse_registry(read(0x81000000, 0xc00))[-1]
    if last != {'opcode': 0xabcd, 'route': 2, 'disabled': 1, 'data_phase': 2, 'handler': 0x81234560, 'slot': 255}:
        raise ValueError('Registry width/last-slot semantics differ')
    full_result = call(0x8077f108, [0xabce, 0, 0, 0, 0])
    if full_result != 0 or read(0x81000c00, 8) != b'PTPguard':
        raise ValueError(f'Full registry rejection/guard differs: return={full_result}, guard={read(0x81000c00,8).hex()}, last={parse_registry(read(0x81000000,0xc00))[-2:]}, inserted={[x for x in parse_registry(read(0x81000000,0xc00)) if x["opcode"]==0xabce]}')
    return {'engine': 'pinned Unicorn 2.1.4 MIPS32 little endian, synthetic 24KC CPU model', 'instructions_executed': instruction_count,
        'scope': 'native insertion/lookup on host-seeded synthetic registry; packet handler attempts separately labeled; no USB, filesystem, peripherals or camera execution',
        'stubs': [f'{address:08x}' for address in stubs],
        'full_initialization_attempt': initialization,
        'application_registration': {'status': 'not-executed', 'basis': 'static instruction assertions/direct Ghidra only'},
        'seed_origin': 'host-supplied from static registration findings; not native initializer output',
        'synthetic_conditions': {'registry_pointer': 0x81000000, 'registry_bytes': 0xc00},
        'seeded_records': [final[n] for n in (0x100c, 0x100d, 0x9005, 0x9006, 0x9002, 0x9003)],
        '9002_handler_verification': handler_verification,
        'lookup_cases': lookup_cases, '9002_handler_cases': handler_cases,
        'final_slot_and_full_rejection_verified': True, 'registration_calls': registration_calls}


def build_report(workspace, source, native):
    if digest(source.read_bytes()) != BASELINE: raise ValueError('Source differs')
    manifest, raw = load_analysis(workspace); mapping = AddressMap(raw, manifest['regions'])
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    assertions = []
    for address, expected in ASSERTIONS.items():
        decoded = list(decoder.disasm(mapping.read(address, 4), address))
        if len(decoded) != 1 or (decoded[0].mnemonic, decoded[0].op_str) != expected:
            raise ValueError(f'Instruction differs at {address:#x}')
        assertions.append({'address': address, 'bytes_sha256': digest(mapping.read(address, 4))})
    corroboration = check_dossiers(native, mapping, digest(raw), FUNCTIONS)
    emulation = emulate_registry(mapping, native)
    return {'schema_version': 1, 'source_sha256': BASELINE, 'analysis_sha256': digest(raw),
        'method': 'authenticated Capstone and direct Ghidra analysis plus bounded synthetic instruction execution; not REA Evidence',
        'camera_commands_issued': False, 'camera_executed': False, 'selected_instructions_emulated': True,
        'instruction_checks': assertions, 'native_corroboration': corroboration, 'emulation': emulation,
        'contracts': [
            {'id': 'ptp.handler_registry', 'status': 'static-and-synthetic-verified',
             'table_pointer': 0x80898e7c, 'records': 256, 'record_bytes': 12,
             'layout': {'opcode_u16': 0, 'route_u8': 2, 'disabled_u8': 3, 'data_phase_u32': 4, 'handler_u32': 8},
             'lookup': 0x8077f050, 'insertion': 0x8077f108, 'initialize': 0x8077f204,
             'ownership': 'initializer allocates 0xc00 bytes through80020980; runtime global table; no external buffer ownership inferred',
             'constraints': 'empty opcode0 means free slot; lookup is unsigned16; insertion truncates flag bytes; higher-level registration updates existing records'},
            {'id': 'ptp.vendor9002', 'status': 'state-changing-route-verified',
             'registration': 0x8057ac40, 'handler': 0x8057db04, 'route': 0, 'data_phase': 1,
             'arguments': 'packet opcode u16+6, first parameter u32+c; response pointera3',
             'side_effects': 'parameter1 with nonzero8065ebdd calls8063b3bc(0); parameter2 with zero byte calls8063b3bc(1)',
             'endpoint': 0x8063b3bc, 'endpoint_behavior': 'capture/display-related calls and sleeps, then writes8065ebdd; exact UI purpose remains inferred',
             'return': 'handler returns1, writes response length12 and code2001 even for tested no-op parameters',
             'constraint': 'advertisement/data-in phase does not establish read-only behavior; no command is allowlisted'},
            {'id': 'ptp.vendor9003', 'status': 'queued-route-verified',
             'registration': 0x8057ac40, 'route': 1, 'local_handler': 0,
             'dispatcher': 0x80779e00, 'event': 0x8800, 'consumer': 0x80634c18,
             'behavior': 'queued HCE branch recognizes9002/9003 and acknowledges through8063b85c; no arbitrary memory-read contract established',
             'ambiguity': '8057db04 also contains a9003 branch that changes settings, but9003 is registered on route1; do not claim that local branch is active'},
            {'id': 'ptp.vendor_object_transfer', 'status': 'registration-verified',
             'operations': [{'opcode': 0x9005, 'same_handler_as': 0x100c, 'handler': 0x80781028, 'data_phase': 2},
                            {'opcode': 0x9006, 'same_handler_as': 0x100d, 'handler': 0x807815a0, 'data_phase': 0}],
             'meaning': 'shares standard object-upload handlers; no memory-address or passive diagnostic semantics established',
             'constraint': 'these entry addresses are interior labels in existing Ghidra functions; registration is verified, full handler file-write behavior is not recovered here'},
            {'id': 'ptp.debug_bridge_search', 'status': 'unresolved',
             'search_boundary': 'selected registrations, local9002 handler, command dispatcher and HCE consumer; no whole-program absence claim',
             'conclusion': 'no reviewed PTP operation supplies a safe ConfigMem/GetMem bridge in this path',
             'dependency': 'existing USB mode6/debug handlers require an independently verified entry and valid memory map; normal PTP presence does not satisfy recovery'}],
        'gates': {'safe_ptp_memory_backup_route': False, 'software_unbootable_recovery_verified': False, 'code_trial_allowed': False},
        'limitations': ['Source firmware identity is verified; exact installed firmware bytes are not.',
            'Synthetic conditions do not establish live configuration flags or current table contents.',
            'No PTP operation, USB control request, mode switch, file write or firmware update is sent.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=WORKSPACE)
    parser.add_argument('--source', type=Path, default=ROOT / 'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--native', type=Path, default=ROOT / 'derived/native-analysis-complete/application')
    parser.add_argument('--output', type=Path, default=ROOT / 'evidence/ptp-vendor-contracts.json')
    args = parser.parse_args()
    if args.output.exists(): raise FileExistsError('Choose a new output path')
    report = build_report(args.workspace, args.source, args.native)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as handle: json.dump(report, handle, indent=2); handle.write('\n')
    print(json.dumps({'contracts': len(report['contracts']), 'native_dossiers': len(FUNCTIONS),
        'emulated_instructions': report['emulation']['instructions_executed'], 'code_trial_allowed': False}))


if __name__ == '__main__': main()
