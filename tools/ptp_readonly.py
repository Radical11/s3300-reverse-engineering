"""Narrow standard-PTP data-to-read transport through the existing Windows WPD driver.

No vendor operation, control/capture, upload, delete, debug or update command.
Imports COM only when opening a physical device; parsers remain portable.
"""
import ctypes as ct
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
MTP = '{4D545058-1A2E-4106-A357-771E0819FC56}'
COMMON = '{F0422A9C-5DC8-4440-B5BD-5DF28835658A}'
ALLOWED = {0x1001: 0, 0x1004: 0, 0x1005: 1, 0x1007: 3, 0x1008: 1, 0x1009: 1}
MAX_TRANSFER = 64 * 1024 * 1024


def validate_read(opcode, params, bound):
    if (type(opcode) is not int or opcode not in ALLOWED or len(params) != ALLOWED[opcode]
            or type(bound) is not int or not 0 < bound <= MAX_TRANSFER
            or any(type(p) is not int or not 0 <= p <= 0xffffffff for p in params)):
        raise ValueError('Operation outside standard read-only allowlist/bounds')


class Dataset:
    def __init__(self, body):
        if len(body) > 131072: raise ValueError('Oversized metadata dataset')
        self.body, self.offset = body, 0

    def unpack(self, fmt):
        count = struct.calcsize('<' + fmt)
        if self.offset + count > len(self.body): raise ValueError('Truncated metadata dataset')
        fields = struct.unpack_from('<' + fmt, self.body, self.offset)
        self.offset += count
        return fields[0] if len(fields) == 1 else fields

    def string(self):
        count = self.unpack('B')
        if count == 0: return ''
        size = count * 2
        if self.offset + size > len(self.body): raise ValueError('Truncated PTP string')
        raw = self.body[self.offset:self.offset+size]; self.offset += size
        if raw[-2:] != b'\0\0': raise ValueError('Unterminated PTP string')
        value = raw[:-2].decode('utf-16-le')
        if '\0' in value: raise ValueError('Embedded PTP string terminator')
        return value

    def array16(self):
        count = self.unpack('I')
        if count > 4096: raise ValueError('Oversized PTP supported-code array')
        return [self.unpack('H') for _ in range(count)]

    def finish(self):
        if self.offset != len(self.body): raise ValueError('Unexpected trailing metadata')


def device_info(body):
    d = Dataset(body)
    standard, vendor, version = d.unpack('HIH')
    description = d.string(); mode = d.unpack('H')
    arrays = {name: [f'0x{code:04x}' for code in d.array16()]
              for name in ('operations', 'events', 'device_properties', 'capture_formats', 'image_formats')}
    result = dict(standard_version=standard, vendor_extension_id=vendor,
                  vendor_extension_version=version, vendor_extension_description=description,
                  functional_mode=mode, **arrays)
    for name in ('manufacturer', 'model', 'firmware', 'serial'): result[name] = d.string()
    d.finish()
    return result


def storage_info(body):
    d = Dataset(body)
    kind, filesystem, access, capacity, free, images = d.unpack('HHHQQI')
    result = dict(storage_type=kind, filesystem_type=filesystem, access_capability=access,
                  capacity_bytes=capacity, free_bytes=free, free_images=images,
                  description=d.string(), volume_label=d.string())
    d.finish()
    return result


def storage_numeric_fields(body):
    """Decode only the fixed26-byte prefix; do not reinterpret malformed strings."""
    d = Dataset(body)
    kind, filesystem, access, capacity, free, images = d.unpack('HHHQQI')
    return dict(storage_type=kind, filesystem_type=filesystem, access_capability=access,
                capacity_bytes=capacity, free_bytes=free, free_images=images,
                scope='PTP exposed storage only; variable strings not validated; not flash geometry')


class ReadOnlyPTP:
    def __init__(self):
        if sys.platform != 'win32': raise ValueError('Live WPD access requires Windows')
        sys.path.insert(0, str(ROOT/'tools/vendor'))
        from comtypes import GUID
        from comtypes.client import CreateObject, GetModule
        self.GUID, self.CreateObject = GUID, CreateObject
        self.api, self.types = GetModule('PortableDeviceApi.dll'), GetModule('PortableDeviceTypes.dll')
        self.calls, self.device = [], None

    def key(self, guid, pid):
        value = self.api._tagpropertykey(); value.fmtid, value.pid = self.GUID(guid), pid
        return ct.pointer(value)

    def values(self):
        return self.CreateObject(self.types.PortableDeviceValues, interface=self.api.IPortableDeviceValues)

    def __enter__(self):
        manager = self.CreateObject(self.api.PortableDeviceManager)
        count = ct.c_ulong(); manager.GetDevices(ct.POINTER(ct.c_wchar_p)(), ct.pointer(count))
        if count.value > 256: raise ValueError('Device enumeration limit')
        ids = (ct.c_wchar_p * count.value)(); manager.GetDevices(ids, ct.pointer(count))
        matches = [x for x in ids if 'vid_04b0' in x.lower() and 'pid_032a' in x.lower()]
        if len(matches) != 1: raise ValueError('Expected exactly one connected S3300')
        self.device = self.CreateObject(self.api.PortableDeviceFTM)
        client = self.values()
        client.SetUnsignedIntegerValue(self.key('{204D9F0C-2292-4080-9F42-40664E70F859}',9), 0x80000000)
        try: self.device.Open(matches[0], client)
        except Exception:
            self.close(); raise
        return self

    def close(self):
        if self.device is not None:
            try: self.device.Close()
            finally: self.device = None

    def __exit__(self, *args): self.close()

    def _send(self, command, parameters):
        if command not in (13, 15, 17): raise ValueError('Not a data-to-read transport command')
        if command == 13:
            # Recheck at the physical dispatch boundary, including callers that
            # bypass read() or accidentally construct a different COM payload.
            opcode = parameters.GetUnsignedIntegerValue(self.key(MTP,1001))
            if opcode not in ALLOWED: raise ValueError('Operation outside standard read-only allowlist')
            collection = parameters.GetIPortableDevicePropVariantCollectionValue(self.key(MTP,1002))
            count = ct.c_ulong(); collection.GetCount(ct.pointer(count))
            if count.value != ALLOWED[opcode]: raise ValueError('PTP parameter count differs')
            words = []
            for index in range(count.value):
                variant = self.api.tag_inner_PROPVARIANT(); collection.GetAt(index,ct.pointer(variant))
                if variant.vt != 19: raise ValueError('PTP parameter must be unsigned32')
                words.append(int(getattr(variant,variant._fields_[-1][0]).ulVal))
            validate_read(opcode,words,MAX_TRANSFER)
        parameters.SetGuidValue(self.key(COMMON,1001), self.GUID(MTP))
        parameters.SetUnsignedIntegerValue(self.key(COMMON,1002), command)
        parameters.SetUnsignedIntegerValue(self.key('{10E54A3E-052D-4777-A13C-DE7614BE2BC4}',3),1)
        result = self.device.SendCommand(0, parameters)
        hr = result.GetErrorValue(self.key(COMMON,1003))
        if hr: raise ValueError(f'WPD read command failed: HRESULT0x{hr & 0xffffffff:08x}')
        return result

    def read(self, opcode, params, bound):
        validate_read(opcode, params, bound)
        if self.device is None: raise ValueError('Read-only device is not open')
        call = dict(opcode=f'0x{opcode:04x}', parameters=params, maximum_bytes=bound)
        self.calls.append(call)
        parameters = self.values()
        collection = self.CreateObject(self.types.PortableDevicePropVariantCollection,
                                       interface=self.api.IPortableDevicePropVariantCollection)
        for number in params:
            variant = self.api.tag_inner_PROPVARIANT(); variant.vt = 19
            getattr(variant,variant._fields_[-1][0]).ulVal = number
            collection.Add(ct.pointer(variant))
        parameters.SetUnsignedIntegerValue(self.key(MTP,1001),opcode)
        parameters.SetIPortableDevicePropVariantCollectionValue(self.key(MTP,1002),collection)
        result = self._send(13,parameters)
        context = result.GetStringValue(self.key(MTP,1006)); data = bytearray()
        transfer_error = None
        try:
            total = int(result.GetUnsignedLargeIntegerValue(self.key(MTP,1007)))
            call['announced_bytes'] = total
            if not 0 <= total <= bound: raise ValueError('PTP read exceeds declared bound')
            while len(data) < total:
                wanted = min(65536,total-len(data)); request = self.values()
                request.SetStringValue(self.key(MTP,1006),context)
                request.SetUnsignedIntegerValue(self.key(MTP,1008),wanted)
                buffer = (ct.c_ubyte*wanted)(); request.SetBufferValue(self.key(MTP,1012),buffer,wanted)
                chunk = self._send(15,request)
                received = chunk.GetUnsignedIntegerValue(self.key(MTP,1009))
                pointer, length = ct.POINTER(ct.c_ubyte)(), ct.c_ulong()
                chunk._IPortableDeviceValues__com_GetBufferValue(self.key(MTP,1012),ct.pointer(pointer),ct.pointer(length))
                try:
                    if not pointer or not 0 < received <= wanted or length.value < received: raise ValueError('Invalid PTP transfer count/buffer')
                    data.extend(ct.string_at(pointer,received))
                finally:
                    free = ct.windll.ole32.CoTaskMemFree
                    free.argtypes, free.restype = [ct.c_void_p], None
                    free(ct.cast(pointer,ct.c_void_p))
        except Exception as error:
            transfer_error = error; call['transfer_error'] = str(error)
            raise
        finally:
            try:
                request = self.values(); request.SetStringValue(self.key(MTP,1006),context)
                final = self._send(17,request)
                response = final.GetUnsignedIntegerValue(self.key(MTP,1003)); call['response'] = f'0x{response:04x}'
            except Exception as error:
                call['end_transfer_error'] = str(error)
                if transfer_error is None: raise
        if response != 0x2001 or len(data) != total: raise ValueError('PTP operation incomplete')
        call['received_bytes'] = len(data)
        return bytes(data)
