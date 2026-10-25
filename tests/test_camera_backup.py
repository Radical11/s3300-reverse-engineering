import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import camera_backup as backup
from ptp_readonly import Dataset, ReadOnlyPTP, device_info, storage_info, storage_numeric_fields, validate_read


def string(value):
    raw=value.encode('utf-16-le')+b'\0\0'
    return bytes([len(raw)//2])+raw


def device_dataset():
    return (struct.pack('<HIH',100,10,100)+string('Synthetic')+struct.pack('<H',0)
        +struct.pack('<IHH',2,0x1001,0x1004)+struct.pack('<I',0)*4
        +b''.join(string(x) for x in ('Test','S3300','1.1','private-test-serial')))


def storage_dataset():
    return struct.pack('<HHHQQI',3,2,0,1<<35,(1<<35)-1024,100)+string('Card')+string('TEST')


def info(name='test.bin',body=b'abc',storage=0x10001):
    data=bytearray(52)
    struct.pack_into('<IHHI',data,0,storage,0x3000,0,len(body))
    struct.pack_into('<I',data,38,0)
    return bytes(data)+string(name)


class FakePTP:
    def __init__(self,changed=False,fail=False,oversized=False):
        self.calls=[]; self.reads=0; self.changed=changed; self.fail=fail; self.oversized=oversized
    def read(self,op,args,bound):
        validate_read(op,args,bound); self.calls.append({'opcode':f'0x{op:04x}'})
        if op==0x1001:return device_dataset()
        if op==0x1004:return struct.pack('<II',1,0x10001)
        if op==0x1005:return storage_dataset()
        if op==0x1007:return struct.pack('<II',1,0x42)
        if op==0x1008:
            raw=bytearray(info('../unsafe.bin'))
            if self.oversized:struct.pack_into('<I',raw,8,backup.MAX_TRANSFER+1)
            return bytes(raw)
        if op==0x1009:
            self.reads+=1
            if self.fail and self.reads==2:raise OSError('Cable removed')
            return b'bad' if self.changed and self.reads==2 else b'abc'


class CameraBackupTests(unittest.TestCase):
    def test_standard_metadata_layout_and_uint64_capacity(self):
        self.assertEqual(device_info(device_dataset())['operations'],['0x1001','0x1004'])
        self.assertEqual(storage_info(storage_dataset())['capacity_bytes'],1<<35)

    def test_metadata_rejects_truncation_trailing_and_invalid_utf16(self):
        for body in (device_dataset()[:-1],device_dataset()+b'x',b'\0'*8+b'\xff'):
            with self.assertRaises((ValueError,UnicodeError)):device_info(body)
        with self.assertRaises(ValueError):storage_info(storage_dataset()+b'x')
        with self.assertRaises(UnicodeError):Dataset(b'\x02\0\xd8\0\0').string()

    def test_live_storage_string_failure_keeps_fixed_fields_separate(self):
        raw=bytes.fromhex('04000300000000005b77000000000080f96b000000005d010000055300330033003000300000')
        with self.assertRaisesRegex(ValueError,'Unterminated'):storage_info(raw)
        fields=storage_numeric_fields(raw)
        self.assertEqual(fields['capacity_bytes'],2002452480)
        self.assertIn('not flash geometry',fields['scope'])

    def test_vendor_writes_controls_and_bad_bounds_never_reach_transport(self):
        for op,args,bound in ((0x9002,[],1),(0x100b,[1],1),(0x100e,[],1),(0x1009,[True],1),
                              (0x1001,[1],16),(0x1009,[1],backup.MAX_TRANSFER+1),(0x1001,[],0)):
            with self.assertRaises(ValueError):validate_read(op,args,bound)

    def test_dispatch_boundary_rejects_embedded_vendor_opcode(self):
        class Params:
            def GetUnsignedIntegerValue(self,key):return 0x9002
        camera=ReadOnlyPTP.__new__(ReadOnlyPTP)
        camera.key=lambda *args:args
        with self.assertRaisesRegex(ValueError,'allowlist'):camera._send(13,Params())

    def test_twice_read_snapshot_and_offline_verification_do_not_claim_flash(self):
        with tempfile.TemporaryDirectory() as folder:
            report=backup.snapshot(FakePTP(),folder)
            self.assertTrue(report['file_snapshot_complete'])
            self.assertFalse(report['internal_flash_backup']);self.assertFalse(report['calibration_backup'])
            verified=backup.verify_snapshot(folder)
            self.assertEqual(verified['files'],1);self.assertEqual(verified['bytes'],3)
            self.assertFalse(verified['camera_accessed'])
            self.assertTrue((Path(folder)/report['copied_files'][0]['path']).is_relative_to(Path(folder)/'objects'))

    def test_changed_second_read_retains_incomplete_local_copy(self):
        with tempfile.TemporaryDirectory() as folder:
            report=backup.snapshot(FakePTP(changed=True),folder)
            self.assertEqual(report['status'],'incomplete')
            self.assertFalse(report['file_snapshot_complete'])
            self.assertEqual(len(list((Path(folder)/'objects').glob('*'))),1)
            with self.assertRaisesRegex(ValueError,'incomplete'):backup.verify_snapshot(folder)

    def test_cable_failure_retains_manifest_and_does_not_mark_complete(self):
        with tempfile.TemporaryDirectory() as folder:
            report=backup.snapshot(FakePTP(fail=True),folder)
            self.assertIn('Cable removed',report['error'])
            self.assertFalse(json.loads((Path(folder)/'manifest.json').read_text())['file_snapshot_complete'])

    def test_large_object_rejected_before_getobject(self):
        with tempfile.TemporaryDirectory() as folder:
            camera=FakePTP(oversized=True);report=backup.snapshot(camera,folder)
            self.assertEqual(camera.reads,0);self.assertEqual(report['status'],'incomplete')

    def test_corrupted_local_file_and_escape_path_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'snapshot';root.mkdir();report=backup.snapshot(FakePTP(),root)
            (root/report['copied_files'][0]['path']).write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError,'hash/size'):backup.verify_snapshot(root)
            report['copied_files'][0]['path']='../outside.bin'
            (root.parent/'outside.bin').write_bytes(b'abc')
            try:
                (root/'manifest.json').write_text(json.dumps(report))
                with self.assertRaisesRegex(ValueError,'file path'):backup.verify_snapshot(root)
            finally:(root.parent/'outside.bin').unlink()

    def test_duplicate_handles_abort_inventory(self):
        camera=FakePTP();original=camera.read
        def read(op,args,bound):
            return struct.pack('<III',2,0x42,0x42) if op==0x1007 else original(op,args,bound)
        camera.read=read
        with self.assertRaisesRegex(ValueError,'Duplicate'):backup.inventory(camera)

    def test_manifest_cannot_omit_visible_files_while_claiming_completion(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);report=backup.snapshot(FakePTP(),root)
            report.update(copied_files=[],planned_files=0,planned_bytes=0)
            (root/'manifest.json').write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError,'inventory coverage'):backup.verify_snapshot(root)

    def test_contradictory_scope_or_vendor_operation_log_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);report=backup.snapshot(FakePTP(),root)
            for key,value in (('calibration_backup',True),('camera_writes',True),('vendor_operations',['0x9002'])):
                changed={**report,key:value};(root/'manifest.json').write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError,'unsupported'):backup.verify_snapshot(root)
            changed={**report,'calls':[{'opcode':'0x9002'}]};(root/'manifest.json').write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError,'unsupported operation'):backup.verify_snapshot(root)

    def test_invalid_destination_is_rejected_before_any_worker(self):
        with tempfile.TemporaryDirectory() as folder,patch('camera_backup.subprocess.run') as run:
            root=Path(folder);(root/'derived').mkdir();(root/'samples').mkdir()
            for output,files in ((root/'outside.json',False),(root/'derived',False),(root/'derived/copy',True)):
                with self.assertRaises(ValueError):backup.acquire(output,files=files,root=root)
            run.assert_not_called()

    def test_worker_timeout_preserves_interruption(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'derived').mkdir()
            with patch('camera_backup.subprocess.run',side_effect=backup.subprocess.TimeoutExpired('worker',1)):
                report=backup.acquire(root/'derived/metadata.json',root=root,timeout=1)
            self.assertEqual(report['status'],'interrupted')
            self.assertFalse(report['file_snapshot_complete'])

    def test_timeout_after_completed_checkpoint_cannot_keep_complete_flag(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'samples').mkdir()
            def timeout(*args,**kwargs):
                manifest=root/'samples/backup/manifest.json'
                manifest.write_text(json.dumps({'status':'file_snapshot_complete','file_snapshot_complete':True}))
                raise backup.subprocess.TimeoutExpired('worker',1)
            with patch('camera_backup.subprocess.run',side_effect=timeout):
                report=backup.acquire(root/'samples/backup',files=True,root=root,timeout=1)
            self.assertEqual(report['status'],'interrupted');self.assertFalse(report['file_snapshot_complete'])

    def test_partial_metadata_remains_distinct_from_transport_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'derived').mkdir()
            def partial(*args,**kwargs):
                (root/'derived/meta.json').write_text(json.dumps({'status':'metadata_partial',
                    'metadata_complete':False,'metadata_errors':[{'error':'Unterminated PTP string'}]}))
                return backup.subprocess.CompletedProcess('worker',0,'','')
            with patch('camera_backup.subprocess.run',side_effect=partial):
                report=backup.acquire(root/'derived/meta.json',root=root)
            self.assertEqual(report['status'],'metadata_partial');self.assertEqual(report['metadata_error_count'],1)


if __name__=='__main__':unittest.main()
