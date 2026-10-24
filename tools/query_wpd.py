"""Bounded read-only WPD introspection of Nikon S3300, retaining its driver.

Only WPD introspection command IDs 11 and 18 are allowed. No raw PTP opcode,
capture, vendor execution, storage write, RAM read, or driver change is exposed.
Run: python tools/query_wpd.py
"""
from pathlib import Path
import argparse
import ctypes as ct
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def worker(storage=False):
    sys.path.insert(0, str(ROOT / "tools/vendor"))
    from comtypes import GUID
    from comtypes.client import CreateObject, GetModule
    api = GetModule("PortableDeviceApi.dll")
    types = GetModule("PortableDeviceTypes.dll")
    common = "{F0422A9C-5DC8-4440-B5BD-5DF28835658A}"
    mtp = "{4D545058-1A2E-4106-A357-771E0819FC56}"

    def progress(s):
        print(s, file=sys.stderr, flush=True)

    def key(guid, pid, typ=api._tagpropertykey):
        k = typ()
        k.fmtid = GUID(guid)
        k.pid = pid
        return ct.pointer(k)

    def err(e):
        return {"error": str(e), "hresult": f"0x{e.hresult & 0xffffffff:08x}" if hasattr(e, "hresult") else None}

    progress("Enumerating WPD devices")
    manager = CreateObject(api.PortableDeviceManager)
    n = ct.c_ulong()
    manager.GetDevices(ct.POINTER(ct.c_wchar_p)(), ct.pointer(n))
    if n.value > 256:
        raise ValueError("Device enumeration exceeds limit")
    ids = (ct.c_wchar_p * n.value)()
    manager.GetDevices(ids, ct.pointer(n))
    matching = [x for x in ids if "vid_04b0" in x.lower() and "pid_032a" in x.lower()]
    report = {"method": "Windows WPD COM, local DLL-generated typelibs, read-only access",
              "enumerated_device_count": n.value, "matching_device_count": len(matching),
              "match": "USB VID04b0 PID032a", "devices": [],
              "allowed_sendcommand_ids": [11, 18],
              "raw_ptp_commands_sent": [], "driver_changes": False,
              "storage_enumeration_requested": storage,
              "sources": [
                  "https://learn.microsoft.com/en-us/windows/win32/api/portabledeviceapi/nf-portabledeviceapi-iportabledevice-open",
                  "https://learn.microsoft.com/en-us/windows/win32/wpd_sdk/wpd-command-mtp-ext-get-supported-vendor-opcodes",
                  "https://learn.microsoft.com/en-us/windows/win32/wpd_sdk/wpd-command-mtp-ext-get-vendor-extension-description",
                  "https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/PortableDevice.h",
                  "https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/WpdMtpExtensions.h"],
              "limitations": ["Advertised vendor operation codes do not establish what they do or a RAM-read route.",
                              "WPD supported command PROPERTYKEYs are not a complete raw PTP operation list.",
                              "No GetDeviceInfo opcode passthrough was attempted."]}
    if len(matching) != 1:
        report["status"] = "Expected exactly one matching Nikon device; no connection opened"
        return report
    for device_id in matching:
        device = CreateObject(api.PortableDeviceFTM)
        item = {"pnp_device_id": device_id, "desired_access": "GENERIC_READ 0x80000000"}
        report["devices"].append(item)
        client = CreateObject(types.PortableDeviceValues, interface=api.IPortableDeviceValues)
        client.SetUnsignedIntegerValue(key("{204D9F0C-2292-4080-9F42-40664E70F859}", 9), 0x80000000)
        progress("Opening matched Nikon device read-only")
        try:
            device.Open(device_id, client)
            item["open_succeeded"] = True
            progress("Reading WPD supported command keys")
            try:
                commands = device.Capabilities().GetSupportedCommands()
                count = ct.c_ulong()
                commands.GetCount(ct.pointer(count))
                if count.value > 4096:
                    raise ValueError("Supported command count exceeds limit")
                keys = []
                for i in range(count.value):
                    k = api._tagpropertykey()
                    commands.GetAt(i, ct.pointer(k))
                    keys.append({"fmtid": str(k.fmtid), "pid": k.pid})
                item["supported_wpd_commands"] = keys
            except Exception as e:
                item["supported_wpd_commands"] = err(e)
            progress("Reading Nikon DEVICE identity properties")
            try:
                props = device.Content().Properties()
                values = props.GetValues("DEVICE", None)
                identity = {}
                for name, pid in [("firmware", 3), ("protocol", 6), ("manufacturer", 7), ("model", 8)]:
                    try:
                        identity[name] = values.GetStringValue(key("{26D4979A-E643-4626-9E2B-736DC0C92FDC}", pid))
                    except Exception as e:
                        identity[name] = err(e)
                item["identity_properties"] = identity
            except Exception as e:
                item["identity_properties"] = err(e)
            if storage:
                progress("Enumerating at most 16 direct DEVICE children read-only")
                content = device.Content()
                enumerator = content.EnumObjects(0, "DEVICE", None)
                children = []
                item["storage_children"] = children
                free = ct.windll.ole32.CoTaskMemFree
                free.argtypes = [ct.c_void_p]
                free.restype = None
                for _ in range(16):
                    identifiers = (ct.c_void_p * 1)()
                    fetched = ct.c_ulong()
                    enumerator._IEnumPortableDeviceObjectIDs__com_Next(
                        1, ct.cast(identifiers, ct.POINTER(ct.c_wchar_p)), ct.pointer(fetched))
                    if fetched.value == 0:
                        item["storage_child_enumeration_complete"] = True
                        break
                    if fetched.value != 1 or not identifiers[0]:
                        raise ValueError("Unexpected bounded WPD enumeration result")
                    try:
                        object_id = ct.wstring_at(identifiers[0])
                    finally:
                        free(identifiers[0])
                    child = {"object_id": object_id}
                    children.append(child)
                    try:
                        values = content.Properties().GetValues(object_id, None)
                        try:
                            child["name"] = values.GetStringValue(key("{EF6B490D-5CD8-437A-AFFC-DA8B60EE4A3C}", 4))
                        except Exception as e:
                            child["name"] = err(e)
                        storage_guid = "{01A3057A-74D6-4E80-BEA7-DC4C212CE50A}"
                        for name, pid in (("storage_type_raw", 2), ("access_capability_raw", 11)):
                            try:
                                child[name] = values.GetUnsignedIntegerValue(key(storage_guid, pid))
                            except Exception as e:
                                child[name] = err(e)
                        for name, pid in (("capacity_bytes", 4), ("free_bytes", 5)):
                            try:
                                child[name] = int(values.GetUnsignedLargeIntegerValue(key(storage_guid, pid)))
                            except Exception as e:
                                child[name] = err(e)
                    except Exception as e:
                        child["property_error"] = err(e)
                else:
                    item["storage_child_enumeration_complete"] = False
                    item["storage_child_limit_reached"] = 16
                continue
            item["introspection"] = []
            for command_id in (11, 18):
                assert command_id in (11, 18)
                progress(f"Read-only MTP extension introspection WPD command {command_id}")
                call = {"wpd_command_id": command_id, "category": mtp, "ioctl_access": "FILE_READ_ACCESS"}
                item["introspection"].append(call)
                try:
                    params = CreateObject(types.PortableDeviceValues, interface=api.IPortableDeviceValues)
                    params.SetGuidValue(key(common, 1001), GUID(mtp))
                    params.SetUnsignedIntegerValue(key(common, 1002), command_id)
                    params.SetUnsignedIntegerValue(key("{10E54A3E-052D-4777-A13C-DE7614BE2BC4}", 3), 1)
                    result = device.SendCommand(0, params)
                    hr = result.GetErrorValue(key(common, 1003))
                    call["driver_hresult"] = f"0x{hr & 0xffffffff:08x}"
                    if hr:
                        continue
                    if command_id == 18:
                        call["vendor_extension_description"] = result.GetStringValue(key(mtp, 1014))
                    else:
                        collection = result.GetIPortableDevicePropVariantCollectionValue(key(mtp, 1005))
                        count = ct.c_ulong()
                        collection.GetCount(ct.pointer(count))
                        if count.value > 4096:
                            raise ValueError("Vendor opcode list exceeds limit")
                        ops = []
                        for i in range(count.value):
                            v = api.tag_inner_PROPVARIANT()
                            collection.GetAt(i, ct.pointer(v))
                            if v.vt != 19:
                                raise ValueError(f"Expected VT_UI4, received VT {v.vt}")
                            union_name = v._fields_[-1][0]
                            ops.append(int(getattr(v, union_name).ulVal))
                        call["vendor_opcodes"] = [f"0x{x:04x}" for x in ops]
                except Exception as e:
                    call.update(err(e))
        except Exception as e:
            item["connection_error"] = err(e)
        finally:
            progress("Closing read-only WPD connection")
            try:
                device.Close()
            except Exception as e:
                item["close_error"] = err(e)
    report["status"] = "Completed bounded read-only introspection"
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worker", action="store_true")
    ap.add_argument("--storage", action="store_true", help="Read direct DEVICE child/storage metadata only")
    ap.add_argument("--evidence", type=Path, default=ROOT / "evidence/wpd-device-info.json",
                    help="New evidence file; existing reports are never overwritten")
    args = ap.parse_args()
    if args.worker:
        try:
            print(json.dumps(worker(storage=args.storage)))
        except Exception as e:
            print(json.dumps({"status": "worker_failed", "error": str(e)}))
        return
    evidence = args.evidence
    if evidence.exists():
        raise ValueError("Evidence exists; refusing to overwrite")
    try:
        arguments = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker"]
        if args.storage:
            arguments.append("--storage")
        run = subprocess.run(arguments,
                             capture_output=True, text=True, timeout=40)
        result = json.loads(run.stdout)
        result["worker_exit_code"] = run.returncode
        result["progress"] = run.stderr.splitlines()
    except subprocess.TimeoutExpired as e:
        progress = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else e.stderr
        result = {"status": "timeout", "timeout_seconds": 40,
                  "progress": (progress or "").splitlines(),
                  "note": "Worker process terminated; no control, capture or raw vendor operations were allowed"}
    with evidence.open("x", encoding="utf-8") as out:
        json.dump(result, out, indent=2)
        out.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
