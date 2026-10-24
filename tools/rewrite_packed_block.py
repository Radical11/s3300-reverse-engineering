"""Rewrite a type-2 block while preserving its tables and payload allocation.

Keep original literal/match tokens whenever they produce the desired bytes with
the new history. Replace only incompatible tokens with existing literal codes.
Reject missing codes or insufficient padding; never move a header or table.
Every result is checked by both the production decoder and independent zlib.
This module does not build an updater or communicate with a camera.
"""
from decode_firmware import BitReader, decode_block, decode_symbol
from validate_decoded_firmware import expand_table, transcode


def rewrite_block(table_a, table_b, payload, original, desired,
                  old_history=b"", new_history=b""):
    if len(original) != len(desired):
        raise ValueError("Decoded length must not change")
    if len(old_history) > 32768 or len(new_history) > 32768:
        raise ValueError("Dictionary exceeds 32 KiB")
    decoded, _ = decode_block(table_a, table_b, payload, len(original), old_history)
    if decoded != original:
        raise ValueError("Original block does not match supplied decoded bytes")
    _, codes = expand_table(table_a)
    literal_codes = {}
    for code, (value, flags, _) in sorted(codes.items(), key=lambda pair: (len(pair[0]), pair[0])):
        if flags == 0:
            literal_codes.setdefault(value, code)
    source_bits = "".join(f"{byte:08b}" for byte in payload)
    reader = BitReader(payload)
    output = bytearray(new_history)
    start = len(output)
    parts = []
    preserved = replaced = emitted_literals = 0
    while True:
        bit_start = reader.position
        value, tag = decode_symbol(table_a, reader)
        if tag == 0 and value == 256:
            parts.append(source_bits[bit_start:reader.position])
            break
        offset = len(output)-start
        if tag == 0:
            actual = bytes([value])
            length = 1
        else:
            length = value+reader.read(tag >> 1)
            encoded, flags = decode_symbol(table_b, reader, distance=True)
            if flags:
                raise ValueError("Unexpected distance flags")
            extra = encoded >> 2
            backward = ((encoded & 3) << extra)+1+reader.read(extra)
            if not 1 <= backward <= min(len(output), 32768):
                # The original token may no longer have available new history.
                actual = None
            else:
                # Include overlapping copies without mutating the real output.
                seed = bytes(output[-backward:])
                actual = (seed*((length+len(seed)-1)//len(seed)))[:length]
        expected = desired[offset:offset+length]
        if len(expected) != length:
            raise ValueError("Token exceeds desired block")
        if actual == expected:
            parts.append(source_bits[bit_start:reader.position])
            preserved += 1
        else:
            try:
                parts.extend(literal_codes[byte] for byte in expected)
            except KeyError as error:
                raise ValueError(f"No existing literal code for byte {error.args[0]}") from error
            replaced += 1
            emitted_literals += length
        output.extend(expected)
    encoded_bits = "".join(parts)
    if bytes(output[start:]) != desired:
        raise ValueError("Rewritten output incomplete")
    if len(encoded_bits) > len(payload)*8:
        raise ValueError("Rewritten tokens exceed existing payload allocation")
    encoded_bits += "0"*(len(payload)*8-len(encoded_bits))
    candidate = int(encoded_bits, 2).to_bytes(len(payload), "big")
    production, statistics = decode_block(table_a, table_b, candidate, len(desired), new_history)
    independent, independent_statistics = transcode(candidate, table_a, table_b, len(desired), new_history)
    if production != desired or independent != desired:
        raise ValueError("Independent rewrite verification failed")
    return candidate, {"preserved_tokens": preserved, "replaced_tokens": replaced,
                       "replacement_literal_tokens": emitted_literals,
                       "payload_bytes": len(payload), "production": statistics,
                       "independent": independent_statistics,
                       "two_decoders_exactly_match_desired": True}
