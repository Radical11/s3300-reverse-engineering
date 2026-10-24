"""Read-only standard PTP fallback through the existing WPD driver.

Only GetStorageIDs, GetObjectHandles, GetObjectInfo and GetObject are allowed.
No vendor opcodes, writes, driver replacement or update execution.
"""
import argparse
import ctypes as ct
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MTP = "{4D545058-1A2E-4106-A357-771E0819FC56}"
COMMON = "{F0422A9C-5DC8-4440-B5BD-5DF28835658A}"
ALLOWED = {0x1004: 0, 0x1007: 3, 0x1008: 1, 0x1009: 1}


def array32(data, limit=128):
    if len(data) < 4:
        raise ValueError("Truncated PTP array")
    count, = struct.unpack_from("<I", data)
    if count > limit or len(data) != 4+4*count:
        raise ValueError("Invalid or oversized PTP array")
    return list(struct.unpack_from("<"+"I"*count, data, 4))


def object_info(data):
    if len(data) < 53:
        raise ValueError("Truncated PTP ObjectInfo")
    count = data[52]
    end = 53+2*count
    if not count or end > len(data) or data[end-2:end] != b"\0\0":
        raise ValueError("Invalid PTP filename")
    return {"storage": struct.unpack_from("<I", data)[0],
            "format": struct.unpack_from("<H", data, 4)[0],
            "size": struct.unpack_from("<I", data, 8)[0],
            "parent": struct.unpack_from("<I", data, 38)[0],
            "filename": data[53:end-2].decode("utf-16-le")}


def worker():
    from stage_wpd_trial import verified_payload, EXPECTED
    payload = verified_payload()
    sys.path.insert(0, str(ROOT/"tools/vendor"))
    from comtypes import GUID
    from comtypes.client import CreateObject, GetModule
    api = GetModule("PortableDeviceApi.dll")
    types = GetModule("PortableDeviceTypes.dll")
    report = {"method": "Read-only standard PTP over existing WPD MTP extension interface",
              "calls": [], "camera_flashed": False, "writes": [],
              "staged_and_readback_verified": False}

    def key(guid, pid):
        value = api._tagpropertykey()
        value.fmtid, value.pid = GUID(guid), pid
        return ct.pointer(value)

    def values():
        return CreateObject(types.PortableDeviceValues, interface=api.IPortableDeviceValues)

    free = ct.windll.ole32.CoTaskMemFree
    free.argtypes, free.restype = [ct.c_void_p], None
    manager = CreateObject(api.PortableDeviceManager)
    count = ct.c_ulong()
    manager.GetDevices(ct.POINTER(ct.c_wchar_p)(), ct.pointer(count))
    if count.value > 256:
        raise ValueError("Device enumeration limit")
    ids = (ct.c_wchar_p*count.value)()
    manager.GetDevices(ids, ct.pointer(count))
    matching = [x for x in ids if "vid_04b0" in x.lower() and "pid_032a" in x.lower()]
    if len(matching) != 1:
        raise ValueError("Expected one S3300")
    device, client = CreateObject(api.PortableDeviceFTM), values()
    client.SetUnsignedIntegerValue(key("{204D9F0C-2292-4080-9F42-40664E70F859}", 9), 0x80000000)

    def send(command, parameters):
        parameters.SetGuidValue(key(COMMON, 1001), GUID(MTP))
        parameters.SetUnsignedIntegerValue(key(COMMON, 1002), command)
        parameters.SetUnsignedIntegerValue(key("{10E54A3E-052D-4777-A13C-DE7614BE2BC4}", 3), 1)
        result = device.SendCommand(0, parameters)
        hr = result.GetErrorValue(key(COMMON, 1003))
        if hr:
            raise ValueError(f"WPD command {command} returned HRESULT 0x{hr & 0xffffffff:08x}")
        return result

    def read(opcode, params, bound):
        if opcode not in ALLOWED or len(params) != ALLOWED[opcode] or not 0 < bound <= len(payload):
            raise ValueError("Operation outside read-only allowlist")
        call = {"opcode": f"0x{opcode:04x}", "params": params, "maximum_bytes": bound}
        report["calls"].append(call)
        print("Standard PTP read " + call["opcode"], file=sys.stderr, flush=True)
        parameters, collection = values(), CreateObject(types.PortableDevicePropVariantCollection,
                                                        interface=api.IPortableDevicePropVariantCollection)
        for number in params:
            variant = api.tag_inner_PROPVARIANT()
            variant.vt = 19
            getattr(variant, variant._fields_[-1][0]).ulVal = number
            collection.Add(ct.pointer(variant))
        parameters.SetUnsignedIntegerValue(key(MTP, 1001), opcode)
        parameters.SetIPortableDevicePropVariantCollectionValue(key(MTP, 1002), collection)
        result = send(13, parameters)
        context = result.GetStringValue(key(MTP, 1006))
        data = bytearray()
        try:
            total = int(result.GetUnsignedLargeIntegerValue(key(MTP, 1007)))
            call["announced_bytes"] = total
            if total > bound:
                raise ValueError("PTP read exceeds expected bound")
            while len(data) < total:
                wanted = min(65536, total-len(data))
                request = values()
                request.SetStringValue(key(MTP, 1006), context)
                request.SetUnsignedIntegerValue(key(MTP, 1008), wanted)
                buffer = (ct.c_ubyte*wanted)()
                request.SetBufferValue(key(MTP, 1012), buffer, wanted)
                chunk = send(15, request)
                received = chunk.GetUnsignedIntegerValue(key(MTP, 1009))
                pointer, length = ct.POINTER(ct.c_ubyte)(), ct.c_ulong()
                chunk._IPortableDeviceValues__com_GetBufferValue(key(MTP, 1012), ct.pointer(pointer), ct.pointer(length))
                try:
                    if not 0 < received <= wanted or length.value < received:
                        raise ValueError("Invalid PTP transfer count")
                    data.extend(ct.string_at(pointer, received))
                finally:
                    free(ct.cast(pointer, ct.c_void_p))
        finally:
            request = values()
            request.SetStringValue(key(MTP, 1006), context)
            final = send(17, request)
            response = final.GetUnsignedIntegerValue(key(MTP, 1003))
            call["response"] = f"0x{response:04x}"
        if response != 0x2001 or len(data) != total:
            raise ValueError("PTP operation did not complete successfully")
        call["received_bytes"] = len(data)
        return bytes(data)

    try:
        device.Open(matching[0], client)
        stores = array32(read(0x1004, [], 1024))
        if len(stores) != 1:
            raise ValueError("Expected one PTP storage")
        roots = array32(read(0x1007, [stores[0], 0, 0xffffffff], 1024))
        folders = []
        for handle in roots:
            info = object_info(read(0x1008, [handle], 4096))
            if info["filename"].casefold() == "firmware" and info["format"] == 0x3001:
                folders.append(handle)
        if len(folders) != 1:
            raise ValueError("Expected one FIRMWARE folder")
        files = array32(read(0x1007, [stores[0], 0, folders[0]], 1024))
        if len(files) != 1:
            raise ValueError("Expected one staged object")
        info = object_info(read(0x1008, files, 4096))
        report["file_info"] = info
        if info["filename"].casefold() != "firmware.bin" or info["size"] != len(payload):
            raise ValueError("Staged filename/size does not match candidate")
        data = read(0x1009, files, len(payload))
        report.update(readback_bytes=len(data), readback_sha256=hashlib.sha256(data).hexdigest())
        if data != payload or report["readback_sha256"] != EXPECTED:
            raise ValueError("PTP readback differs from candidate")
        report.update(status="staged_not_flashed", staged_and_readback_verified=True)
    except Exception as error:
        report.update(status="stopped", error=str(error))
    finally:
        device.Close()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker()))
        return
    if not args.evidence or args.evidence.exists():
        raise ValueError("Supply a new --evidence path")
    try:
        run = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker"],
                             capture_output=True, text=True, timeout=120)
        report = json.loads(run.stdout)
        report["progress"] = run.stderr.splitlines()
        report["worker_exit_code"] = run.returncode
    except subprocess.TimeoutExpired:
        report = {"status": "read_only_worker_timeout", "staged_and_readback_verified": False}
    with args.evidence.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
