"""Read-only PTP metadata and twice-read file snapshots, never an internal-flash backup."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from ptp_readonly import ReadOnlyPTP, device_info, storage_info, storage_numeric_fields, MAX_TRANSFER
from read_ptp_staged import array32, object_info

ROOT = Path(__file__).resolve().parents[1]
MAX_OBJECTS = 4096
MAX_TOTAL = 512 * 1024 * 1024
TOOL_HASHES = {name: hashlib.sha256((ROOT/'tools'/name).read_bytes()).hexdigest()
               for name in ('camera_backup.py','ptp_readonly.py','read_ptp_staged.py')}


def sha(body): return hashlib.sha256(body).hexdigest()


def checkpoint(path, report):
    temporary = path.with_name(path.name + '.tmp')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)


def inventory(transport):
    report = {'schema_version': 1, 'method': 'Standard PTP reads through existing Windows WPD driver',
        'acquisition_tool_hashes': TOOL_HASHES,
        'device_info': None, 'metadata_errors': [], 'storages': [], 'objects': [],
        'internal_flash_backup': False, 'calibration_backup': False, 'recovery_verified': False,
        'camera_writes': False, 'vendor_operations': [], 'driver_changes': False,
        'limitations': ['Only objects exposed by normal PTP are visible',
            'Storage capacity is not installed flash geometry or a RAM measurement',
            'A copied firmware.bin is a card file, not a readback of installed firmware']}
    try: report['device_info'] = device_info(transport.read(0x1001, [], 131072))
    except Exception as error:
        report['metadata_errors'].append({'operation': 'GetDeviceInfo', 'error': str(error)})
    ids = array32(transport.read(0x1004, [], 1024), limit=128)
    if len(ids) != len(set(ids)) or not ids: raise ValueError('Missing or duplicate storage IDs')
    seen = set()
    for storage in ids:
        store = {'storage_id': storage}
        try:
            raw = transport.read(0x1005, [storage], 4096)
            store.update(dataset_bytes=len(raw), dataset_sha256=sha(raw), dataset_hex=raw.hex())
            store['numeric_fields'] = storage_numeric_fields(raw)
            store['info'] = storage_info(raw)
        except Exception as error:
            store['error'] = str(error)
            report['metadata_errors'].append({'operation': 'GetStorageInfo', 'storage': storage, 'error': str(error)})
        report['storages'].append(store)
        handles = array32(transport.read(0x1007, [storage, 0, 0], 4+4*MAX_OBJECTS), limit=MAX_OBJECTS)
        if len(handles) != len(set(handles)) or len(seen)+len(handles) > MAX_OBJECTS:
            raise ValueError('Duplicate handles or object inventory exceeds limit')
        for handle in handles:
            if not handle or handle in seen: raise ValueError('Zero or duplicate global object handle')
            seen.add(handle)
            info = object_info(transport.read(0x1008, [handle], 4096))
            if info['storage'] != storage: raise ValueError('Object changed storage during inventory')
            report['objects'].append({'handle': handle, **info})
    report['metadata_complete'] = not report['metadata_errors']
    return report


def snapshot(transport, output):
    output = Path(output)
    manifest = output/'manifest.json'
    report = {'schema_version': 1, 'status': 'inventory_in_progress', 'copied_files': [],
              'file_snapshot_complete': False, 'internal_flash_backup': False, 'recovery_verified': False}
    checkpoint(manifest,report)
    try:
        report.update(inventory(transport))
        files = [item for item in report['objects'] if item['format'] != 0x3001]
        if any(item['size'] > MAX_TRANSFER for item in files) or sum(item['size'] for item in files) > MAX_TOTAL:
            raise ValueError('Snapshot exceeds64MiB per file or512MiB total; no oversized data requested')
        report.update(status='copy_in_progress', planned_files=len(files), planned_bytes=sum(item['size'] for item in files))
        checkpoint(manifest,report)
        for item in files:
            # Handles are local object identities, not persistent firmware addresses.
            name = re.sub(r'[^A-Za-z0-9._-]', '_', item['filename'])[:96].strip('.') or 'object'
            target = output/'objects'/f"{item['handle']:08x}-{name}"
            target.parent.mkdir(exist_ok=True)
            before = object_info(transport.read(0x1008, [item['handle']], 4096))
            if before != {key:item[key] for key in before}: raise ValueError('Object metadata changed before copy')
            first = transport.read(0x1009, [item['handle']], max(1,item['size']))
            if len(first) != item['size']: raise ValueError('Object length differs from inventory')
            with target.open('xb') as stream: stream.write(first)
            first_hash = sha(first)
            second = transport.read(0x1009, [item['handle']], max(1,item['size']))
            after = object_info(transport.read(0x1008, [item['handle']], 4096))
            if sha(second) != first_hash or len(second) != len(first) or before != after:
                raise ValueError('Object bytes or metadata changed across two reads')
            if sha(target.read_bytes()) != first_hash: raise ValueError('Local file readback differs')
            report['copied_files'].append(dict(handle=item['handle'], filename=item['filename'],
                path=target.relative_to(output).as_posix(), bytes=len(first), sha256=first_hash,
                device_reads_equal=True, local_readback_equal=True))
            report['calls'] = transport.calls
            checkpoint(manifest,report)
        # Re-enumeration cannot prove hidden or omitted objects; it detects visible changes.
        final = inventory(transport)
        signature = lambda data: sorted(data['objects'],key=lambda item:item['handle'])
        if signature(final) != signature(report): raise ValueError('Visible object inventory changed during snapshot')
        report.update(status='file_snapshot_complete', file_snapshot_complete=True,
                      final_inventory_equal=True, calls=transport.calls)
    except Exception as error:
        report.update(status='incomplete', file_snapshot_complete=False, error=str(error), calls=transport.calls)
    checkpoint(manifest,report)
    return report


def verify_snapshot(output):
    output = Path(output).resolve(strict=True)
    report = json.loads((output/'manifest.json').read_text(encoding='utf-8'))
    if (report.get('schema_version') != 1 or report.get('status') != 'file_snapshot_complete' or report.get('file_snapshot_complete') is not True
            or report.get('internal_flash_backup') is not False or report.get('recovery_verified') is not False
            or report.get('calibration_backup') is not False or report.get('camera_writes') is not False
            or report.get('driver_changes') is not False or report.get('vendor_operations') != []):
        raise ValueError('Snapshot is incomplete or claims unsupported backup/recovery coverage')
    if any(call.get('opcode') not in ('0x1001','0x1004','0x1005','0x1007','0x1008','0x1009')
           for call in report['calls']): raise ValueError('Snapshot log contains an unsupported operation')
    seen = set(); total = 0
    expected = {item['handle']: item for item in report['objects'] if item['format'] != 0x3001}
    if len(expected) != report['planned_files'] or report.get('final_inventory_equal') is not True:
        raise ValueError('Snapshot inventory coverage differs')
    copied_handles = set()
    for item in report['copied_files']:
        original = expected.get(item['handle'])
        if (original is None or item['handle'] in copied_handles or original['size'] != item['bytes']
                or original['filename'] != item['filename']): raise ValueError('Snapshot object coverage differs')
        copied_handles.add(item['handle'])
        relative = Path(item['path']); unresolved = output/relative; path = unresolved.resolve(strict=True)
        if (relative.is_absolute() or not path.is_relative_to(output/'objects') or path in seen
                or unresolved.is_symlink() or not path.is_file()): raise ValueError('Invalid snapshot file path')
        seen.add(path)
        if item.get('device_reads_equal') is not True or item.get('local_readback_equal') is not True:
            raise ValueError('Missing independent readback check')
        body = path.read_bytes()
        if len(body) != item['bytes'] or sha(body) != item['sha256']: raise ValueError('Snapshot file hash/size differs')
        total += len(body)
    if len(seen) != report['planned_files'] or total != report['planned_bytes']:
        raise ValueError('Snapshot file coverage differs')
    return dict(verified=True, files=len(seen), bytes=total, internal_flash_backup=False, calibration_backup=False,
                recovery_verified=False, camera_accessed=False)


def backup_status(root=ROOT, *, verify_files=False):
    from flash_trial_payloads import BASELINE
    scope_path = root/'evidence/backup-scope.json'
    scope = json.loads(scope_path.read_text(encoding='utf-8')) if scope_path.is_file() else {}
    if scope and scope.get('source_sha256') != BASELINE: raise ValueError('Backup scope source identity differs')
    record_path = root/'evidence/camera-file-backup-2026-10-25.json'
    record = json.loads(record_path.read_text(encoding='utf-8')) if record_path.is_file() else None
    result = dict(schema_version=1, source_sha256=BASELINE,
        required_components=scope.get('required_backup_components',[]), file_snapshot_record=record,
        private_manifest_present=False,
        files_verified_now=False, complete_internal_backup=False, unbootable_software_recovery=False,
        executable_trial_allowed=False, camera_accessed=False)
    if record:
        if record.get('source_sha256') != BASELINE: raise ValueError('File snapshot record baseline differs')
        manifest = (root/record['private_manifest']).resolve()
        if not manifest.is_relative_to((root/'samples').resolve()): raise ValueError('Private snapshot must stay under samples/')
        result['private_manifest_present'] = manifest.is_file()
    if record and verify_files:
        if sha(manifest.read_bytes()) != record['private_manifest_sha256']: raise ValueError('Private manifest differs from recorded snapshot')
        result['current_file_verification'] = verify_snapshot(manifest.parent)
        result['files_verified_now'] = True
    return result


def acquire(output, *, files=False, timeout=300, root=ROOT):
    output = Path(output).resolve()
    base = (root/('samples' if files else 'derived')).resolve()
    if output == base or not output.is_relative_to(base) or output.exists() or not output.parent.is_dir():
        raise ValueError('Choose a new output under samples/ for files or derived/ for metadata; parent must exist')
    if files:
        output.mkdir(); report_path = output/'manifest.json'
    else: report_path = output
    checkpoint(report_path,{'schema_version':1,'status':'starting','file_snapshot_complete':False,
                            'internal_flash_backup':False,'recovery_verified':False})
    args = [sys.executable,'-B',str(Path(__file__).resolve()),'--worker',str(output)]
    if files: args.append('--files')
    try:
        process = subprocess.run(args,capture_output=True,text=True,timeout=timeout)
        report = json.loads(report_path.read_text(encoding='utf-8'))
        if process.returncode != 0:
            report.update(status='incomplete',file_snapshot_complete=False,worker_exit_code=process.returncode,worker_error=process.stderr[-2000:])
            checkpoint(report_path,report)
    except subprocess.TimeoutExpired:
        report = json.loads(report_path.read_text(encoding='utf-8'))
        report.update(status='interrupted',file_snapshot_complete=False,error='Read-only worker timed out; incomplete files retained',timeout_seconds=timeout,
                      transport_cleanup_verified=False,device_transport_state='unknown after worker termination')
        checkpoint(report_path,report)
    return dict(output=str(output),status=report['status'],file_snapshot_complete=report.get('file_snapshot_complete',False),
        copied_files=len(report.get('copied_files',[])),internal_flash_backup=False,recovery_verified=False,
        camera_writes=False,driver_changes=False,metadata_parse_complete=report.get('metadata_complete',False),
        metadata_error_count=len(report.get('metadata_errors',[])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',type=Path)
    parser.add_argument('--files',action='store_true')
    args = parser.parse_args()
    if not args.worker: parser.error('Use s3300.py camera-metadata or backup-files')
    report_path = args.worker/'manifest.json' if args.files else args.worker
    base = (ROOT/('samples' if args.files else 'derived')).resolve()
    resolved = args.worker.resolve()
    if resolved == base or not resolved.is_relative_to(base) or not report_path.is_file():
        parser.error('Worker requires an already prepared local output')
    prepared = json.loads(report_path.read_text(encoding='utf-8'))
    if prepared.get('status') != 'starting' or prepared.get('internal_flash_backup') is not False:
        parser.error('Worker output is not a new prepared acquisition')
    try:
        with ReadOnlyPTP() as transport:
            if args.files: report = snapshot(transport,args.worker)
            else:
                report = inventory(transport)
                report.update(status='metadata_complete' if report['metadata_complete'] else 'metadata_partial',calls=transport.calls)
                checkpoint(report_path,report)
        return 0 if report['status'] in ('metadata_complete','metadata_partial','file_snapshot_complete') else 1
    except Exception as error:
        report = json.loads(report_path.read_text(encoding='utf-8'))
        report.update(status='incomplete',file_snapshot_complete=False,error=str(error)); checkpoint(report_path,report)
        return 1


if __name__ == '__main__': raise SystemExit(main())
