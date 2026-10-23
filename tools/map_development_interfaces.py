"""Extract source-bound developer command contracts from validated S3300 v1.1.

Offline only. This does not expose or invoke a debug transport and does not
change firmware. Commands are inventory entries, not instructions to run them.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / 'vendor'))
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

ROOT = Path(__file__).resolve().parents[1]
ELF_SHA = '15b39f407ca9ba322af07e64ea07562b2234848c030a26ca2be2e48c42966040'
SOURCE_SHA = '2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b'


def digest(data):
    return hashlib.sha256(data).hexdigest()


class AddressMap:
    def __init__(self, data, regions):
        self.data = data
        self.regions = regions

    def read(self, address, length):
        if length < 0:
            raise ValueError('Negative read length')
        matches = [r for r in self.regions if r['virtual_start'] <= address
                   and address + length <= r['virtual_start'] + r['size']]
        if len(matches) != 1:
            raise ValueError('Read must fit one uniquely backed region')
        region = matches[0]
        offset = region['analysis_elf_offset'] + address - region['virtual_start']
        if offset < 0 or offset + length > len(self.data):
            raise ValueError('Backing bytes truncated')
        return self.data[offset:offset+length]

    def text(self, address, maximum=512):
        result = bytearray()
        for offset in range(maximum):
            byte = self.read(address+offset, 1)[0]
            if byte == 0:
                try:
                    return result.decode('ascii')
                except UnicodeDecodeError as exc:
                    raise ValueError('Non-ASCII command string') from exc
            if byte not in (9, 10, 13) and not 32 <= byte < 127:
                raise ValueError('Non-printable command string')
            result.append(byte)
        raise ValueError('Unterminated command string')

    def command(self, address):
        name, arguments, description, handler = struct.unpack('<4I', self.read(address, 16))
        if not handler % 4 == 0:
            raise ValueError('Unaligned MIPS32 handler')
        self.read(handler, 4)
        return {'entry_address': address, 'record_size': 16,
                'name': self.text(name), 'arguments': self.text(arguments),
                'description': self.text(description), 'handler': handler,
                'pointer_fields': {'name': name, 'arguments': arguments, 'description': description}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'evidence/development-interfaces.json')
    parser.add_argument('--listings', type=Path, default=ROOT/'derived/development-interfaces')
    args = parser.parse_args()
    manifest = json.loads((ROOT/'derived/v1.1-analysis/manifest.json').read_text())
    elf_path = Path(manifest['elf_file'])
    data = elf_path.read_bytes()
    source = ROOT/'sources/extracted-v1.1/S3300Update/firmware/firmware.bin'
    if digest(data) != ELF_SHA or manifest['elf_sha256'] != ELF_SHA or digest(source.read_bytes()) != SOURCE_SHA:
        raise ValueError('Unsupported source or analysis ELF')
    for r in manifest['regions']:
        body = data[r['analysis_elf_offset']:r['analysis_elf_offset']+r['size']]
        if len(body) != r['size'] or digest(body) != r['sha256']:
            raise ValueError('Region identity mismatch')
    if args.output.exists() or args.listings.exists():
        raise FileExistsError('Refusing to overwrite prior evidence')
    address_map = AddressMap(data, manifest['regions'])
    entries = [0x8042b8dc, 0x8042b8ec, 0x8042b8fc, 0x8042b90c, 0x8042b91c,
               0x8042b92c, 0x8042bba0, 0x8089830c, 0x8089851c]
    expected = ['cachecostcheck', 'cpupct', 'cpupcs', 'cpupcp', 'cpupce', 'cpupcr', 'cpu', 'ct', 'ctm']
    commands = [address_map.command(a) for a in entries]
    if [c['name'] for c in commands] != expected:
        raise ValueError('Unexpected developer command table identity')
    details = {
        'cachecostcheck': 'Overhead measurement control; changes test state. No runtime timing is collected here.',
        'cpupct': 'Synthetic CPU-counter stress test, may disable interrupts; excluded from initial observation protocol.',
        'cpupcs': 'Parses two signed integers; validates first in unsigned range 0..3; calls 0x800b1fc4(a0=cache selector,a1=interrupt flag). Underlying API treats flag==1 as interrupt-disable path.',
        'cpupcp': 'Calls 0x800b2080; stops counters and conditionally restores interrupt state saved by start.',
        'cpupce': 'Calls 0x800b20b8 to reset counter state; not a passive read.',
        'cpupcr': 'Passes stack buffer to 0x800b20d0 then prints its six u32 fields through 0x80400b28; reading counters does not itself start/reset them.',
        'cpu': 'Parses optional integer 0/1; either initializes load checker through 0x800c7ec4 or requests statistics through 0x800c8008. Initialization changes monitoring state.',
        'ct': 'Parses count; zero/unspecified becomes 0x50. Reads an array at 0x80817388, skips indices20..29, prints remaining entries. No bounds clamp established; never invoke with an arbitrary count.',
        'ctm': 'Parses integer; nonzero starts timing through 0x8000fc88(0x50,1); values other than1 may execute string through0x8022f43c. Zero calls0x806f6c9c(0),then0x806f6c94.',
    }
    for command in commands:
        command['static_contract'] = details[command['name']]
        command['runtime_exposure'] = 'Unverified console/transport reachability; inventory only'
    decoder = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    specs = [('cpu_counter_handlers', 0x80400ea8, 0x180),
             ('counter_register_api', 0x800b1fc4, 0x168),
             ('counter_formatter', 0x80400b28, 0x13c),
             ('cpu_load_handler', 0x80403468, 0xa0),
             ('capture_array_reader', 0x80580468, 0xac),
             ('capture_timing_handler', 0x805862ec, 0x90),
             ('gamma_cache_loader', 0x8021c7a8, 0x1b8),
             ('gamma_converter_entry', 0x8021bd3c, 0x148),
             ('gamma_converter_result', 0x8021c390, 0x64),
             ('gamma_channel_extraction', 0x8021c960, 0xdc),
             ('gamma_cache_reset', 0x8021c76c, 0x3c),
             ('vendor_control_listener', 0x807958e0, 0x2a0),
             ('vendor_control_application_gate', 0x80749528, 0x88),
             ('vendor_control_application_filter', 0x8057923c, 0x90),
             ('transfer_direction_routing', 0x80796070, 0x98),
             ('getmem_transfer_candidate', 0x8079de34, 0x1d8)]
    args.listings.mkdir(parents=True)
    windows = []
    for label, address, size in specs:
        raw = address_map.read(address, size)
        decoded = list(decoder.disasm(raw, address))
        if sum(i.size for i in decoded) != size:
            raise ValueError('Incomplete static window decode')
        listing = args.listings/(label+'.asm')
        listing.write_text('; Static analyst window; no execution, proven function boundary or reachability claim.\n'
                           + '\n'.join(f'{i.address:08x} {i.bytes.hex():8} {i.mnemonic:10} {i.op_str}' for i in decoded)+'\n')
        windows.append({'label': label, 'virtual_start': address, 'size': size,
                        'sha256': digest(raw), 'linear_decode_bytes': size, 'listing': str(listing)})
    counter_fields = [(0, 'hits', 0xb0801068), (4, 'misses', 0xb080106c),
                      (8, 'instructions', 0xb0801060), (12, 'prefetch_hits', 0xb0801078),
                      (16, 'prefetch_misses', 0xb080107c), (20, 'clocks', 0xb0801064)]
    report = {'method': 'Static table extraction and bounded disassembly, validated application v1.1',
        'source_sha256': SOURCE_SHA, 'analysis_elf_sha256': ELF_SHA,
        'command_record': {'size': 16, 'endianness': 'little',
                           'fields': ['name pointer','argument-help pointer','description pointer','handler pointer'],
                           'corroboration': 'Nine independently decoded records have matching ASCII identity and reviewed handler behavior.'},
        'commands': commands,
        'cpu_counters': {'read_api': 0x800b20d0, 'read_buffer_bytes': 24,
            'fields': [{'offset': o, 'name': n, 'mmio_address': a} for o,n,a in counter_fields],
            'cache_selectors': ['MCPU_DCACHE','MCPU_ICACHE','SCPU_DCACHE','SCPU_ICACHE'],
            'initial_profile_default': 'If a verified transport is later available, first preserve interrupts and use selector0/flag0. No command is issued by this tool.',
            'constraint': 'Counter registers are device MMIO. Never access them through host process memory; API inventory is not a runtime observation.'},
        'gamma_efficiency_candidate': {'loader': 0x8021c7a8, 'cache_base': 0x808c4eec,
            'cache_slot_count': 10, 'size_array_offset': 0, 'raw_pointer_array_offset': 40,
            'cache_hit_converter_call': 0x8021c804, 'cache_miss_converter_call': 0x8021c8d0,
            'converter': 0x8021bd3c, 'allocation_sizes': [0x994,0x4000],
            'allocation_sites': [0x8021be48,0x8021be70], 'output_pointer_write': 0x8021c3c0,
            'reset_routine': 0x8021c76c,
            'finding': 'The loader caches raw resource size/pointer. Every successful hit runs converter again, which allocates output plus scratch and returns a distinct output pointer. Converted output is not stored back in this raw-resource cache.',
            'ownership_constraint': 'Downstream channel-extractor0x8021c960 copies from generated result+0x194 then frees generated result at0x8021ca08. Sharing a cached converted pointer without ownership changes would create invalid frees/use-after-free.',
            'candidate': 'Measure converter frequency/cost; if worthwhile cache immutable converted data separately and preserve caller-owned results or implement explicit refcount/ownership.',
            'measured_gain': None, 'safe_patch_ready': False},
        'usb_accessibility': {'vendor_control_listener': 0x807958e0,
            'listener_source_diagnostic': 'Zcam/Zagents/Agents/Ptp/Standard/PtpStandardVendor.c',
            'request_buffer_bytes': 8, 'request_type_offset': 0, 'request_code_offset': 1,
            'value_offset': 2, 'index_offset': 4, 'length_offset': 6,
            'application_gate': 0x80749528, 'application_mode_required': 7,
            'application_filter': 0x8057923c, 'accepted_request_code': 0x41,
            'accepted_index': 4, 'outcome': 'For mode7 only, application hook handles bRequest0x41/wIndex4 via bounded copy from global806599a0. Other modes or requests return nonzero and enter generic handling or stall paths, depending request direction.',
            'getmem_handler': 0x8079de34, 'getmem_pointer': 0x80899660,
            'setmem_or_monitor_pointer': 0x80899658,
            'routing_api': 0x80796070,
            'routing': 'Transport selector0 uses0x800db0e4 plus0x80795ce0; selector1 uses0x80796424 and device agent lookup0x8078bdac. This establishes separate transfer paths but not external host request framing for GetMem.',
            'missing': ['Generic command dispatcher identification and command-number/table-index mapping',
                        'Confirmed active interface/endpoints and enabled mode on installed v1.0',
                        'Safe bounded read-only memory/flash request protocol and backup coverage'],
            'runtime_or_device_access_performed': False},
        'accessibility_next_steps': ['Decode the command dispatcher that consumes the eight-byte handler records around80899658; enumerate IDs/directions before exposing any CLI.',
            'Start any future developer interface with an allowlist of identity/version/status/profile-read operations and explicit typed lengths; separate memory writes, console execution and flash operations.',
            'Use existing capture timing and counter APIs to locate actual bottlenecks before changing processing or polling.',
            'Implement a selectable developer menu through verified command registration only after UI event ownership/persistence and recovery are understood.'],
        'windows': windows,
        'source_unchanged': digest(source.read_bytes()) == SOURCE_SHA,
        'limitations': ['Static v1.1 software evidence only; no installed-v1.0 RAM dump or device timing.',
                        'MMIO and command table addresses are for offline analysis, not host memory or blind camera invocation.',
                        'No firmware optimization, runtime developer access, custom menu or performance benefit has been demonstrated.']}
    with args.output.open('x',encoding='utf-8')as f:
        json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({'commands':len(commands),'windows':len(windows),'source_unchanged':report['source_unchanged']}))


if __name__=='__main__':
    main()
