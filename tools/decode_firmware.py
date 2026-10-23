"""Decode the S3300 v1.1 type-2 streams without executing firmware or using USB.

The two-branch comb tables were inferred from the supplied image. Every block
must yield its declared output length followed by EOB 256 and zero padding.
A 32 KiB dictionary carries between blocks of one ELF segment only.

This is an analysis decoder, NOT an updater or a repacker.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct

EXPECTED_SHA256 = '2c44b1fd2849cff633bd71f64ffb272d1f2f76c85961f47c947f6cd42d7a498b'
ROOT = Path(__file__).resolve().parents[1]


def digest(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


class DecodeError(ValueError):
    pass


class BitReader:
    """Source byte order, most-significant bit first, bounded reads."""
    def __init__(self, data: bytes):
        self.data = data
        self.position = 0

    def peek(self, count: int) -> int:
        if count < 0 or self.position + count > len(self.data) * 8:
            raise DecodeError('Bit read exceeds payload')
        result = 0
        for bit in range(self.position, self.position + count):
            result = (result << 1) | ((self.data[bit // 8] >> (7 - bit % 8)) & 1)
        return result

    def read(self, count: int) -> int:
        value = self.peek(count)
        self.position += count
        return value

    def remaining_is_zero(self) -> bool:
        position = self.position
        partial = position % 8
        if partial and self.data[position // 8] & ((1 << (8 - partial)) - 1):
            return False
        return not any(self.data[(position + 7) // 8:])


def fields(word: int) -> tuple[int, int, int, int]:
    return word & 3, (word >> 2) & 0x1ff, (word >> 11) & 15, word >> 15


def decode_symbol(table: tuple[int, ...], bits: BitReader, *, distance: bool = False) -> tuple[int, int]:
    """Return leaf value and tag; traversal consumes Huffman bits, not LZ extras.

    Type 1 stores two comb chains. After side 0, zero continues and one stops;
    after side 1, one continues and zero stops. The last leaf needs no stop bit.
    Type 0 is an expanded direct lookup. Its leaf count includes length extra
    bits for table A, so subtract those to obtain Huffman-only consumption.
    """
    node = 0
    for _ in range(32):
        if not 0 <= node < len(table):
            raise DecodeError('Table index out of bounds')
        kind, index, width, count = fields(table[node])
        if kind == 3:
            return index, width
        if kind == 1:
            if not width or not count:
                raise DecodeError('Empty comb chain')
            side = bits.read(1)
            chain_length = count if side else width
            node = index + 1 + (width if side else 0)
            for _ in range(chain_length - 1):
                if bits.read(1) != side:
                    break
                node += 1
        elif kind == 0:
            if not width or not count or count > width:
                raise DecodeError('Invalid direct table dimensions')
            node = index + bits.peek(width)
            if not 0 <= node < len(table):
                raise DecodeError('Direct table index out of bounds')
            child_kind, value, tag, leaf_count = fields(table[node])
            if child_kind != 3:
                bits.read(width)
                continue
            extra_count = (tag >> 1) if tag & 1 and not distance else 0
            consume = count + leaf_count - extra_count
            if not 0 < consume <= width:
                raise DecodeError('Invalid direct leaf bit consumption')
            bits.read(consume)
            return value, tag
        else:
            raise DecodeError(f'Unknown table instruction {kind}')
    raise DecodeError('Table traversal depth exceeded')


def decode_block(table_a: tuple[int, ...], table_b: tuple[int, ...], payload: bytes,
                 output_size: int, history: bytes = b'') -> tuple[bytes, dict]:
    if len(history) > 32768:
        raise DecodeError('History exceeds 32 KiB')
    if not payload or len(payload) % 128:
        raise DecodeError('Payload is not a nonempty multiple of 128 bytes')
    bits = BitReader(payload)
    output = bytearray(history)
    start = len(output)
    literals = matches = 0
    while True:
        value, tag = decode_symbol(table_a, bits)
        if tag == 0:
            if value == 256:
                if len(output) - start != output_size:
                    raise DecodeError('EOB does not coincide with declared output length')
                break
            if value > 255:
                raise DecodeError('Invalid literal')
            output.append(value)
            literals += 1
        elif tag & 1:
            length = value + bits.read(tag >> 1)
            if not 3 <= length <= 258:
                raise DecodeError('Invalid match length')
            encoded_distance, distance_tag = decode_symbol(table_b, bits, distance=True)
            if distance_tag != 0:
                raise DecodeError('Unexpected distance leaf tag')
            distance_extra = encoded_distance >> 2
            if distance_extra > 13:
                raise DecodeError('Distance extra-bit count exceeds DEFLATE range')
            backward = ((encoded_distance & 3) << distance_extra) + 1 + bits.read(distance_extra)
            if not 1 <= backward <= min(len(output), 32768):
                raise DecodeError('Match references unavailable history')
            for _ in range(length):
                output.append(output[-backward])
            matches += 1
        else:
            raise DecodeError('Unexpected literal/length leaf tag')
        if len(output) - start > output_size:
            raise DecodeError('Decoded output exceeds declared length')
    if not bits.remaining_is_zero():
        raise DecodeError('Nonzero data after EOB')
    return bytes(output[start:]), {
        'decoded_bytes': output_size, 'literal_tokens': literals, 'match_tokens': matches,
        'eob_bit_end': bits.position, 'padding_bits': len(payload) * 8 - bits.position,
        'eob_verified': True, 'zero_padding_verified': True,
    }


def decode_image(source: Path, framing_path: Path, output_dir: Path) -> dict:
    data = source.read_bytes()
    source_hash = digest(data)
    if source_hash != EXPECTED_SHA256:
        raise DecodeError('Source is not the expected S3300 v1.1 image')
    framing = json.loads(framing_path.read_text(encoding='utf-8'))
    if framing['input_sha256'] != source_hash:
        raise DecodeError('Framing evidence has a different source identity')
    if output_dir.exists():
        raise FileExistsError(f'Refusing to overwrite output directory: {output_dir}')
    output_dir.mkdir(parents=True)
    segments = []
    for segment in framing['segments']:
        complete = bytearray()
        cursor = segment['carrier_offset']
        blocks = []
        for block in segment['blocks']:
            if block['header']['carrier_offset'] != cursor:
                raise DecodeError('Noncontiguous block framing')
            kind, declared, payload_size, a_size, b_size = struct.unpack_from('<IIIHH', data, cursor)
            if kind != 2 or not declared or not a_size or not b_size or a_size % 4 or b_size % 4:
                raise DecodeError('Invalid type-2 framing')
            a_start = cursor + 16
            b_start = a_start + a_size
            payload_start = b_start + b_size
            end = payload_start + payload_size
            if end > segment['carrier_end_exclusive']:
                raise DecodeError('Block extends beyond segment')
            for key, region_start, size in [('table_a', a_start, a_size), ('table_b', b_start, b_size),
                                             ('payload', payload_start, payload_size)]:
                region = block[key]
                if (region['carrier_offset'] != region_start or region['size'] != size
                        or region['sha256'] != digest(data[region_start:region_start + size])):
                    raise DecodeError(f'{key} disagrees with source-bound framing')
            if declared != block['declared_output_bytes']:
                raise DecodeError('Declared output length disagrees with framing')
            a_table = struct.unpack_from(f'<{a_size // 4}I', data, a_start)
            b_table = struct.unpack_from(f'<{b_size // 4}I', data, b_start)
            decoded, statistics = decode_block(a_table, b_table, data[payload_start:end], declared,
                                               bytes(complete[-32768:]))
            blocks.append({'index': block['index'], 'carrier_offset': cursor,
                           'virtual_start': segment['elf_p_vaddr'] + len(complete),
                           'sha256': digest(decoded), **statistics})
            complete.extend(decoded)
            cursor = end
        if cursor != segment['carrier_end_exclusive'] or len(complete) != segment['elf_p_memsz']:
            raise DecodeError('Decoded segment disagrees with ELF layout')
        filename = f'segment-{segment["carrier_offset"]:08x}.bin'
        (output_dir / filename).write_bytes(complete)
        segments.append({'carrier_offset': segment['carrier_offset'], 'virtual_start': segment['elf_p_vaddr'],
                         'decoded_bytes': len(complete), 'sha256': digest(complete),
                         'file': str((output_dir / filename).resolve()), 'block_count': len(blocks), 'blocks': blocks})
    if digest(source.read_bytes()) != source_hash:
        raise DecodeError('Source changed during decoding')
    report = {'method': 'Inferred two-comb/direct Huffman tables and DEFLATE-family LZ77 token decoding',
              'source_path': str(source.resolve()), 'source_sha256': source_hash,
              'source_hash_unchanged': True, 'segment_count': len(segments),
              'block_count': sum(s['block_count'] for s in segments),
              'decoded_bytes': sum(s['decoded_bytes'] for s in segments),
              'all_block_lengths_eob_and_zero_padding_verified': True,
              'dictionary': 'Last 32768 decoded bytes carry between blocks of each segment; reset between segments',
              'limitations': ['Analysis-only decoded segments; not an update image.',
                              'Decoder self-consistency does not establish update integrity, recovery or hardware execution.',
                              'No device access, patching, repacking or flash writes occur.'],
              'segments': segments}
    (output_dir / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'sources/extracted-v1.1/S3300Update/firmware/firmware.bin')
    parser.add_argument('--framing', type=Path, default=ROOT / 'evidence/packed-segments.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'derived/v1.1-decoded')
    parser.add_argument('--evidence', type=Path, default=ROOT / 'evidence/decoded-segments.json')
    args = parser.parse_args()
    if args.evidence.exists():
        raise FileExistsError(f'Refusing to overwrite evidence: {args.evidence}')
    report = decode_image(args.source, args.framing, args.output)
    with args.evidence.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
        handle.write('\n')
    print(json.dumps({key: report[key] for key in ['segment_count', 'block_count', 'decoded_bytes',
                                                    'all_block_lengths_eob_and_zero_padding_verified']}))


if __name__ == '__main__':
    main()
