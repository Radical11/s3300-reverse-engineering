"""Host layout checks, independent source corroboration and failure rejection."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/"tools"),str(ROOT/"tools/vendor")]
from map_matrix_application import subtype15_register_values,crosscheck_native


def command(coefficients=range(9),offsets=(110,150),auxiliary=0xfffffffe):
    data=bytearray(0x30)
    struct.pack_into("<III",data,0,0x30,15,15)
    struct.pack_into("<9h",data,0x14,*coefficients)
    struct.pack_into("<2h",data,0x26,*offsets)
    struct.pack_into("<I",data,0x2c,auxiliary)
    return data


class MatrixApplicationTests(unittest.TestCase):
    def test_coefficients_offsets_and_auxiliary_are_distinct(self):
        values=subtype15_register_values(command())
        self.assertEqual([r["address"] for r in values],
            [0xb60000c0+4*i for i in range(11)]+[0xb60000fc])
        self.assertEqual([r["value_u32"] for r in values],list(range(9))+[110,150,0xfffffffe])

    def test_signed_halfwords_sign_extend(self):
        result=subtype15_register_values(command([-32768,-1,0,1,32767,4,5,6,7],(-2,-32768)))
        self.assertEqual(result[0]["value_u32"],0xffff8000)
        self.assertEqual(result[1]["value_u32"],0xffffffff)
        self.assertEqual(result[4]["value_u32"],32767)
        self.assertEqual(result[9]["value_u32"],0xfffffffe)
        self.assertEqual(result[10]["value_u32"],0xffff8000)

    def test_alignment_bytes_have_no_register_output(self):
        a=command();b=command();b[0x2a:0x2c]=b"\xff\x7f"
        self.assertEqual(subtype15_register_values(a),subtype15_register_values(b))

    def test_external_command_or_different_mode_rejected(self):
        for length in (0,0x2f,0x31,0x34):
            with self.assertRaises(ValueError):subtype15_register_values(bytes(length))
        for offset,value in ((0,0x34),(4,32),(8,6)):
            data=command();struct.pack_into("<I",data,offset,value)
            with self.assertRaises(ValueError):subtype15_register_values(data)

    def test_native_identity_mismatch_fails_before_dossier_access(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            (path/"image.json").write_text(json.dumps({"executable_sha256":"wrong","language":"MIPS:LE:32:default"}))
            with self.assertRaisesRegex(ValueError,"different analysis"):
                crosscheck_native(None,"expected",path)

    def test_native_architecture_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            (path/"image.json").write_text(json.dumps({"executable_sha256":"expected","language":"wrong"}))
            with self.assertRaisesRegex(ValueError,"architecture"):
                crosscheck_native(None,"expected",path)

    def test_native_imported_byte_mismatch_fails(self):
        class Mapping:
            def read(self,address,size):return bytes(size)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);(path/"functions").mkdir()
            (path/"image.json").write_text(json.dumps({"executable_sha256":"expected","language":"MIPS:LE:32:default"}))
            dossier={"address":"80008f80","decompilation_completed":True,
                "pseudocode":"synthetic fixture","instructions":[{"bytes":"01020304","address":"80008f80"}]}
            (path/"functions/80008f80.json").write_text(json.dumps(dossier))
            with self.assertRaisesRegex(ValueError,"imported bytes"):
                crosscheck_native(Mapping(),"expected",path)

    def test_failed_native_decompilation_is_not_corroboration(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);(path/"functions").mkdir()
            (path/"image.json").write_text(json.dumps({"executable_sha256":"expected","language":"MIPS:LE:32:default"}))
            dossier={"address":"80008f80","decompilation_completed":False}
            (path/"functions/80008f80.json").write_text(json.dumps(dossier))
            with self.assertRaisesRegex(ValueError,"incomplete"):
                crosscheck_native(None,"expected",path)


if __name__=="__main__":unittest.main()
