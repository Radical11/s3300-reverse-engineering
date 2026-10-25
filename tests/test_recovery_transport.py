"""Offline transport layout, identity and memory-boundary rejection tests."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT/'tools/vendor')]
from map_recovery_transport import describe_setup_bytes,describe_config_payload,check_dossiers,ElfBytes


class RecoveryTransportTests(unittest.TestCase):
    def test_observed_setup_fields_use_correct_byte_order(self):
        result=describe_setup_bytes(bytes.fromhex('c01234f178560800'))
        self.assertEqual(result,{'request_type':0xc0,'request':0x12,'value':0xf134,
            'index':0x5678,'length':8,'internal_index':0xf1,'subcommand':0x34})

    def test_setup_size_is_exact(self):
        for n in (0,7,9,64):
            with self.assertRaises(ValueError):describe_setup_bytes(bytes(n))

    def test_config_fields_and_mode1_alias(self):
        payload=struct.pack('<II',0x80123456,0x200)
        self.assertEqual(describe_config_payload(payload,1),
            {'mode':1,'address':0x80123456,'length':0x200,'getmem_mode1_alias':0xa0123456})
        self.assertIsNone(describe_config_payload(payload,16)['getmem_mode1_alias'])

    def test_config_short_or_out_of_byte_mode_rejected(self):
        for payload,mode in ((bytes(7),1),(bytes(8),-1),(bytes(8),256)):
            with self.assertRaises(ValueError):describe_config_payload(payload,mode)

    def test_alias_rule_is_or_and_preserves_already_aliased_address(self):
        result=describe_config_payload(struct.pack('<II',0xa0123456,0),1)
        self.assertEqual(result['getmem_mode1_alias'],0xa0123456)
        self.assertEqual(result['length'],0) # observation, not validation of safety

    def test_native_identity_rejected(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d);(p/'image.json').write_text(json.dumps({'executable_sha256':'other','language':'MIPS:LE:32:default'}))
            with self.assertRaisesRegex(ValueError,'identity'):check_dossiers(p,None,'expected',[])

    def test_imported_bytes_rejected(self):
        class Mapping:
            def read(self,address,size):return bytes(size)
        with tempfile.TemporaryDirectory()as d:
            p=Path(d);(p/'functions').mkdir()
            (p/'image.json').write_text(json.dumps({'executable_sha256':'expected','language':'MIPS:LE:32:default'}))
            fixture={'address':'80000000','decompilation_completed':True,'pseudocode':'synthetic',
                'instructions':[{'bytes':'01020304','address':'80000000'}]}
            (p/'functions/80000000.json').write_text(json.dumps(fixture))
            with self.assertRaisesRegex(ValueError,'instruction differs'):check_dossiers(p,Mapping(),'expected',[0x80000000])

    def test_elf_address_reader_rejects_crossing_or_ambiguous_ranges(self):
        reader=object.__new__(ElfBytes);reader.parts=[(0x1000,b'abcdefgh')]
        self.assertEqual(reader.read(0x1002,3),b'cde')
        with self.assertRaises(ValueError):reader.read(0x1007,2)
        reader.parts.append((0x1000,b'abcdefgh'))
        with self.assertRaises(ValueError):reader.read(0x1000,4)


if __name__=='__main__':unittest.main()
