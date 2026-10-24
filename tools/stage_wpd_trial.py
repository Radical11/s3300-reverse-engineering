"""Inventory or stage the exact label-test file through standard Windows WPD.

Default is read-only. --stage creates firmware/firmware.bin and refuses an
enumerated existing file. The embedded-label existing-path experiment targets
only the project's prior update file; its observed transfer was rejected.
The embedded-label mode requires separate standard-PTP readback after commit.
Does not format, delete, send raw/vendor commands, or start an update.
"""
import argparse
import ctypes as ct
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from flash_trial_payloads import TRIALS, load_trial

ROOT = Path(__file__).resolve().parents[1]
OBJECT = "{EF6B490D-5CD8-437A-AFFC-DA8B60EE4A3C}"
FOLDER = "{27E2E392-A111-48E0-AB0C-E17705A05F85}"
STORAGE = "{01A3057A-74D6-4E80-BEA7-DC4C212CE50A}"
EXPECTED = "c34433c1849ad5e97a2115fc2a67dbecdeb94a4cbb2fdd0dd2bcd25251888312"


def verified_payload(trial="resource-label"):
    if trial == "embedded-label":
        return load_trial(trial)
    if trial != "resource-label":
        raise ValueError("Unknown trial")
    from validate_resource_candidate import verify
    payload = (ROOT/"derived/experimental-flash-trial-01/firmware/firmware.bin").read_bytes()
    verify((ROOT/"sources/extracted-v1.1/S3300Update/firmware/firmware.bin").read_bytes(), payload)
    if hashlib.sha256(payload).hexdigest() != EXPECTED:
        raise ValueError("Not the approved minimal label-test candidate")
    return payload


def worker(stage, readback=False, trial="resource-label", direct_path=False):
    payload = verified_payload(trial) if stage or readback else None
    sys.path.insert(0, str(ROOT/"tools/vendor"))
    from comtypes import GUID
    from comtypes.client import CreateObject, GetModule
    api = GetModule("PortableDeviceApi.dll")
    types = GetModule("PortableDeviceTypes.dll")
    report = {"mode": "stage" if stage else "read-only verification" if readback else "read-only inventory", "camera_flashed": False,
              "trial": trial, "creative_looks_integrated": False,
              "existing_firmware_path_requested": direct_path,
              "file_creation_attempted": False, "folder_creation_attempted": False,
              "staged_and_readback_verified": False, "raw_vendor_commands": [],
              "format_or_delete_operations": [], "events": []}

    def event(message):
        report["events"].append(message)
        print(message, file=sys.stderr, flush=True)

    def key(guid, pid):
        value = api._tagpropertykey()
        value.fmtid, value.pid = GUID(guid), pid
        return ct.pointer(value)

    free = ct.windll.ole32.CoTaskMemFree
    free.argtypes, free.restype = [ct.c_void_p], None

    def take_string(value):
        if not value.value:
            raise ValueError("WPD returned an empty object identifier")
        try:
            return ct.wstring_at(value.value)
        finally:
            free(value.value)

    manager = CreateObject(api.PortableDeviceManager)
    count = ct.c_ulong()
    manager.GetDevices(ct.POINTER(ct.c_wchar_p)(), ct.pointer(count))
    if count.value > 256:
        raise ValueError("Device count exceeds limit")
    ids = (ct.c_wchar_p*count.value)()
    manager.GetDevices(ids, ct.pointer(count))
    matching = [x for x in ids if "vid_04b0" in x.lower() and "pid_032a" in x.lower()]
    if len(matching) != 1:
        raise ValueError("Expected exactly one connected S3300")
    device = CreateObject(api.PortableDeviceFTM)
    client = CreateObject(types.PortableDeviceValues, interface=api.IPortableDeviceValues)
    client.SetUnsignedIntegerValue(key("{204D9F0C-2292-4080-9F42-40664E70F859}", 9),
                                   0xc0000000 if stage else 0x80000000)
    try:
        event("Opening matched S3300 with " + ("read/write" if stage else "read-only") + " WPD access")
        device.Open(matching[0], client)
        content = device.Content()
        props = content.Properties()
        identity = props.GetValues("DEVICE", None)
        firmware = identity.GetStringValue(key("{26D4979A-E643-4626-9E2B-736DC0C92FDC}", 3))
        report["installed_firmware"] = firmware
        if stage and firmware != TRIALS[trial]["installed_firmware"]:
            raise ValueError("Installed version differs from the selected trial baseline")

        def children(parent):
            report["last_wpd_operation"] = "EnumObjects " + parent
            enum = content.EnumObjects(0, parent, None)
            result = []
            for _ in range(128):
                identifier, fetched = ct.c_void_p(), ct.c_ulong()
                report["last_wpd_operation"] = "EnumObjects.Next " + parent
                enum._IEnumPortableDeviceObjectIDs__com_Next(
                    1, ct.cast(ct.pointer(identifier), ct.POINTER(ct.c_wchar_p)), ct.pointer(fetched))
                if fetched.value == 0:
                    return result
                if fetched.value != 1:
                    raise ValueError("Invalid enumeration count")
                object_id = take_string(identifier)
                report["last_wpd_operation"] = "Properties.GetValues " + object_id
                requested = CreateObject(types.PortableDeviceKeyCollection,
                                         interface=api.IPortableDeviceKeyCollection)
                for pid in (4, 7):
                    requested.Add(key(OBJECT, pid))
                try:
                    values = props.GetValues(object_id, requested)
                except Exception as error:
                    result.append({"id": object_id, "name": None, "type": None,
                                   "metadata_error": str(error)})
                    continue
                report["last_wpd_operation"] = "GetStringValue(NAME) " + object_id
                child = {"id": object_id, "name": values.GetStringValue(key(OBJECT, 4))}
                try:
                    child["type"] = str(values.GetGuidValue(key(OBJECT, 7)))
                except Exception as error:
                    child["type"] = None
                    child["type_query_error"] = str(error)
                result.append(child)
            raise ValueError("Direct-child count exceeds bounded inventory limit")

        stores = []
        for child in children("DEVICE"):
            values = props.GetValues(child["id"], None)
            try:
                access = values.GetUnsignedIntegerValue(key(STORAGE, 11))
                capacity = int(values.GetUnsignedLargeIntegerValue(key(STORAGE, 4)))
                available = int(values.GetUnsignedLargeIntegerValue(key(STORAGE, 5)))
            except Exception:
                continue
            stores.append({**child, "access": access, "capacity": capacity, "free": available})
        report["storage"] = stores
        if len(stores) != 1:
            raise ValueError("Expected exactly one card storage object")
        store = stores[0]
        roots = children(store["id"])
        report["card_root"] = roots
        event("Card root enumerated; " + str(len(roots)) + " objects")
        if any(x["name"] is None for x in roots):
            raise ValueError("Cannot identify every card-root entry")
        folders = [x for x in roots if x["name"].casefold() == "firmware"]
        if len(folders) > 1 or (folders and folders[0]["type"] != FOLDER):
            raise ValueError("Ambiguous or non-folder firmware object")

        def verify_readback(folder_id):
            event("Enumerating firmware folder for committed file")
            entries = children(folder_id)
            report["firmware_folder_children"] = entries
            files = [x for x in entries if (x["name"] or "").casefold() == "firmware.bin"]
            report["file_name_metadata_verified"] = len(files) == 1
            if not files and len(entries) == 1 and entries[0]["name"] is None:
                files = entries
            if len(files) != 1:
                raise ValueError("Cannot uniquely locate committed file for readback")
            file_id = files[0]["id"]
            requested = CreateObject(types.PortableDeviceKeyCollection,
                                     interface=api.IPortableDeviceKeyCollection)
            for pid in (6, 11):
                requested.Add(key(OBJECT, pid))
            try:
                values = props.GetValues(file_id, requested)
                for name, pid, getter in (("file_metadata_bytes", 11, values.GetUnsignedLargeIntegerValue),
                                          ("file_format", 6, values.GetGuidValue)):
                    try:
                        result = getter(key(OBJECT, pid))
                        report[name] = int(result) if pid == 11 else str(result)
                    except Exception as error:
                        report[name+"_error"] = str(error)
            except Exception as error:
                report["file_metadata_error"] = str(error)
            event("Requesting default resource read stream")
            report["last_wpd_operation"] = "Resources.GetStream " + file_id
            reader, optimal = ct.POINTER(api.IStream)(), ct.c_ulong()
            content.Transfer()._IPortableDeviceResources__com_GetStream(
                file_id, key("{E81E79BE-34F0-41BF-B53F-F1A06AE87842}", 0),
                0, ct.pointer(optimal), ct.pointer(reader))
            digest, total = hashlib.sha256(), 0
            while total <= len(payload):
                buffer, received = (ct.c_ubyte*65536)(), ct.c_ulong()
                reader._ISequentialStream__com_RemoteRead(buffer, len(buffer), ct.pointer(received))
                if received.value > len(buffer):
                    raise ValueError("Invalid readback count")
                if not received.value:
                    break
                digest.update(bytes(buffer[:received.value]))
                total += received.value
            report.update(readback_bytes=total, readback_sha256=digest.hexdigest())
            if total != len(payload) or digest.hexdigest() != TRIALS[trial]["sha256"]:
                raise ValueError("Device readback does not match candidate")
            report.update(staged_and_readback_verified=True, status="staged_not_flashed")

        if not stage:
            if readback:
                if not folders:
                    raise ValueError("No staged firmware folder found")
                verify_readback(folders[0]["id"])
            else:
                report["status"] = "inventory_complete"
            return report
        if store["access"] != 0 or store["free"] < len(payload):
            raise ValueError("Card does not report writable access and adequate free space")

        def object_values(parent, name, content_type, file_format):
            values = CreateObject(types.PortableDeviceValues, interface=api.IPortableDeviceValues)
            for pid, value in ((3, parent), (4, name), (12, name)):
                values.SetStringValue(key(OBJECT, pid), value)
            values.SetGuidValue(key(OBJECT, 7), GUID(content_type))
            values.SetGuidValue(key(OBJECT, 6), GUID(file_format))
            return values

        if direct_path:
            # The reviewed PTP path constructor (0x80787ac4) accepts a rooted
            # filename. Restrict this to our already-created update file.
            folder_id = store["id"]
            report["target_path"] = "\\FIRMWARE\\FIRMWARE.BIN"
            event("Using fixed existing update path through standard WPD file transfer")
        elif folders:
            folder_id = folders[0]["id"]
        else:
            values = object_values(store["id"], "firmware", FOLDER,
                                   "{30010000-AE6C-4804-98BA-C57B46965FE7}")
            identifier = ct.c_void_p()
            event("Requesting standard WPD creation of firmware folder")
            report["folder_creation_attempted"] = True
            content._IPortableDeviceContent__com_CreateObjectWithPropertiesOnly(
                values, ct.cast(ct.pointer(identifier), ct.POINTER(ct.c_wchar_p)))
            folder_id = take_string(identifier)
            report["folder_created"] = True
        entries = [] if direct_path else children(folder_id)
        if any(x["name"] is None for x in entries):
            raise ValueError("Cannot identify every existing firmware-folder entry; refusing write")
        if any(x["name"].casefold() == "firmware.bin" for x in entries):
            raise ValueError("firmware.bin already exists; refusing overwrite")
        values = object_values(folder_id, "firmware.bin",
                               "{0085E0A6-8D34-45D7-BC5C-447E59C73D48}",
                               "{30000000-AE6C-4804-98BA-C57B46965FE7}")
        if direct_path:
            values.SetStringValue(key(OBJECT, 4), "\\FIRMWARE\\FIRMWARE.BIN")
            values.SetStringValue(key(OBJECT, 12), "\\FIRMWARE\\FIRMWARE.BIN")
        values.SetUnsignedLargeIntegerValue(key(OBJECT, 11), len(payload))
        stream, optimal, cookie = ct.POINTER(api.IStream)(), ct.c_ulong(), ct.c_void_p()
        report["file_creation_attempted"] = True
        event("Requesting standard WPD creation of firmware.bin")
        try:
            content._IPortableDeviceContent__com_CreateObjectWithPropertiesAndData(
                values, ct.pointer(stream), ct.pointer(optimal),
                ct.cast(ct.pointer(cookie), ct.POINTER(ct.c_wchar_p)))
            for offset in range(0, len(payload), 65536):
                chunk = payload[offset:offset+65536]
                buffer = (ct.c_ubyte*len(chunk)).from_buffer_copy(chunk)
                written = ct.c_ulong()
                stream._ISequentialStream__com_RemoteWrite(buffer, len(chunk), ct.pointer(written))
                if written.value != len(chunk):
                    raise ValueError("Short WPD stream write; update has not been started")
            stream.Commit(0)
            report["file_committed"] = True
            event("File committed; verifying full device readback")
        finally:
            if cookie.value:
                free(cookie.value)
        if trial == "embedded-label":
            report["status"] = "file_committed_requires_ptp_readback"
            event("Use standard PTP readback; WPD binary metadata/resource reads are known unsupported")
        else:
            verify_readback(folder_id)
    except Exception as error:
        report.update(status="stopped", error=str(error))
        if hasattr(error, "hresult"):
            report["hresult"] = f"0x{error.hresult & 0xffffffff:08x}"
    finally:
        event("Closing WPD connection")
        try:
            device.Close()
        except Exception as error:
            report["close_error"] = str(error)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", action="store_true")
    parser.add_argument("--trial", choices=tuple(TRIALS), default="resource-label")
    parser.add_argument("--existing-firmware-path", action="store_true",
                        help="Use only the fixed existing update path for the embedded-label trial")
    parser.add_argument("--verify-staged", action="store_true", help="Read back existing file without writing")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if args.stage and args.verify_staged:
        raise ValueError("Choose staging or read-only verification")
    if args.existing_firmware_path and (not args.stage or args.trial != "embedded-label"):
        raise ValueError("Existing-path transfer is restricted to the authorized embedded-label staging trial")
    if args.worker:
        try:
            report = worker(args.stage, args.verify_staged, args.trial, args.existing_firmware_path)
        except Exception as error:
            report = {"status": "worker_failed", "error": str(error),
                      "staged_and_readback_verified": False, "camera_flashed": False}
        print(json.dumps(report))
        return
    if not args.evidence or args.evidence.exists():
        raise ValueError("Supply a new --evidence path")
    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", "--trial", args.trial]
    if args.stage:
        command.append("--stage")
    if args.existing_firmware_path:
        command.append("--existing-firmware-path")
    if args.verify_staged:
        command.append("--verify-staged")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=240)
        report = json.loads(result.stdout)
        report["worker_exit_code"] = result.returncode
    except subprocess.TimeoutExpired as error:
        progress = error.stderr or b""
        if isinstance(progress, bytes):
            progress = progress.decode(errors="replace")
        report = {"status": "timeout_unknown_transfer_state", "progress": progress.splitlines(),
                  "camera_flashed": False, "staged_and_readback_verified": False}
    with args.evidence.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
