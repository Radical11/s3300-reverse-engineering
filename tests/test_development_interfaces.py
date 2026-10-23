import importlib.util
from pathlib import Path
import struct
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/'tools/map_development_interfaces.py'
spec=importlib.util.spec_from_file_location('development_interfaces',SCRIPT)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DevelopmentInterfaceTests(unittest.TestCase):
    def fixture(self):
        data=bytearray(128)
        struct.pack_into('<4I',data,0,0x1020,0x1028,0x1030,0x1040)
        data[32:37]=b'read\0'
        data[40:45]=b'<id>\0'
        data[48:60]=b'Read status\0'
        return module.AddressMap(bytes(data),[{'virtual_start':0x1000,'size':len(data),'analysis_elf_offset':0}])

    def test_command_schema(self):
        result=self.fixture().command(0x1000)
        self.assertEqual((result['name'],result['arguments'],result['description'],result['handler']),
                         ('read','<id>','Read status',0x1040))

    def test_unbacked_read_rejected(self):
        with self.assertRaises(ValueError):self.fixture().read(0xfff,4)
        with self.assertRaises(ValueError):self.fixture().read(0x107f,2)

    def test_negative_length_rejected(self):
        with self.assertRaisesRegex(ValueError,'Negative'):self.fixture().read(0x1000,-1)

    def test_overlapping_map_rejected(self):
        mapping=self.fixture();mapping.regions*=2
        with self.assertRaisesRegex(ValueError,'uniquely'):mapping.read(0x1000,4)

    def test_unterminated_string_rejected(self):
        mapping=module.AddressMap(b'abcd',[{'virtual_start':1,'size':4,'analysis_elf_offset':0}])
        with self.assertRaisesRegex(ValueError,'Unterminated'):mapping.text(1,4)

    def test_nonprintable_string_rejected(self):
        mapping=module.AddressMap(b'\xff\0',[{'virtual_start':1,'size':2,'analysis_elf_offset':0}])
        with self.assertRaisesRegex(ValueError,'Non-printable'):mapping.text(1)

    def test_unaligned_handler_rejected(self):
        mapping=self.fixture();data=bytearray(mapping.data);struct.pack_into('<I',data,12,0x1041);mapping.data=bytes(data)
        with self.assertRaisesRegex(ValueError,'Unaligned'):mapping.command(0x1000)

    def test_truncated_backing_rejected(self):
        mapping=module.AddressMap(b'abc',[{'virtual_start':1,'size':30,'analysis_elf_offset':0}])
        with self.assertRaisesRegex(ValueError,'truncated'):mapping.read(1,4)


if __name__=='__main__':unittest.main()
