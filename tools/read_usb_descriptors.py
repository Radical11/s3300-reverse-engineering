"""Read S3300 configuration descriptors through Windows' existing USB hub.

Only three read-only hub IOCTLs are allowed. GET_DESCRIPTOR is issued only to
the exact VID/PID match, for configuration index zero. No vendor request,
device reset, interface claim, driver replacement or storage write is exposed.
"""
import argparse
import ctypes as ct
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
NODE_INFO = (0x22 << 16) | (258 << 2)
CONNECTION_INFO = (0x22 << 16) | (274 << 2)
GET_DESCRIPTOR = (0x22 << 16) | (260 << 2)
ALLOWED = {NODE_INFO, CONNECTION_INFO, GET_DESCRIPTOR}
SOURCES = [
    "https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/usbioctl/ns-usbioctl-_usb_descriptor_request",
    "https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/usbioctl/ni-usbioctl-ioctl_usb_get_node_connection_information_ex",
]


def parse_configuration(body):
    if len(body) < 9 or body[0:2] != b"\x09\x02":
        raise ValueError("Invalid USB configuration descriptor")
    total = struct.unpack_from("<H", body, 2)[0]
    if not 9 <= total <= 4096 or len(body) != total:
        raise ValueError("USB configuration length differs")
    result = {"total_bytes": total, "declared_interfaces": body[4], "configuration_value": body[5],
              "attributes": body[7], "maximum_power_2ma_units": body[8], "interfaces": [],
              "descriptor_sha256": hashlib.sha256(body).hexdigest()}
    cursor, current = 0, None
    while cursor < total:
        if cursor + 2 > total:
            raise ValueError("Truncated USB descriptor header")
        length, kind = body[cursor:cursor + 2]
        if length < 2 or cursor + length > total:
            raise ValueError("Invalid USB descriptor extent")
        item = body[cursor:cursor + length]
        if kind == 4:
            if length != 9:
                raise ValueError("Invalid USB interface descriptor")
            current = {"number": item[2], "alternate": item[3], "declared_endpoints": item[4],
                       "class": item[5], "subclass": item[6], "protocol": item[7], "endpoints": []}
            result["interfaces"].append(current)
        elif kind == 5:
            if current is None or length < 7:
                raise ValueError("USB endpoint without a valid interface")
            address, attributes = item[2], item[3]
            current["endpoints"].append({"address": address, "address_hex": f"0x{address:02x}",
                "direction": "in" if address & 128 else "out", "number": address & 15,
                "transfer_type": ("control", "isochronous", "bulk", "interrupt")[attributes & 3],
                "max_packet_bytes": struct.unpack_from("<H", item, 4)[0] & 0x7ff,
                "interval_raw": item[6]})
        cursor += length
    unique = {(i["number"], i["alternate"]) for i in result["interfaces"]}
    if len(unique) != len(result["interfaces"]) or len({i["number"] for i in result["interfaces"]}) != result["declared_interfaces"]:
        raise ValueError("USB interface counts/identities differ")
    for interface in result["interfaces"]:
        addresses = [e["address"] for e in interface["endpoints"]]
        if len(addresses) != interface["declared_endpoints"] or len(set(addresses)) != len(addresses):
            raise ValueError("USB endpoint counts/identities differ")
    return result


def worker():
    if sys.platform != "win32":
        raise ValueError("USB hub inventory requires Windows")
    from ctypes import wintypes as w
    setup = ct.WinDLL("setupapi", use_last_error=True)
    kernel = ct.WinDLL("kernel32", use_last_error=True)

    class GUID(ct.Structure):
        _fields_ = [("data", ct.c_ubyte * 16)]

    class Interface(ct.Structure):
        _fields_ = [("cbSize", w.DWORD), ("guid", GUID), ("flags", w.DWORD), ("reserved", ct.c_void_p)]

    guid = GUID.from_buffer_copy(uuid.UUID("f18a0e88-c30c-11d0-8815-00a0c906bed8").bytes_le)
    setup.SetupDiGetClassDevsW.argtypes = [ct.POINTER(GUID), w.LPCWSTR, w.HWND, w.DWORD]
    setup.SetupDiGetClassDevsW.restype = ct.c_void_p
    setup.SetupDiEnumDeviceInterfaces.argtypes = [ct.c_void_p, ct.c_void_p, ct.POINTER(GUID), w.DWORD, ct.POINTER(Interface)]
    setup.SetupDiEnumDeviceInterfaces.restype = w.BOOL
    setup.SetupDiGetDeviceInterfaceDetailW.argtypes = [ct.c_void_p, ct.POINTER(Interface), ct.c_void_p, w.DWORD, ct.POINTER(w.DWORD), ct.c_void_p]
    setup.SetupDiGetDeviceInterfaceDetailW.restype = w.BOOL
    setup.SetupDiDestroyDeviceInfoList.argtypes = [ct.c_void_p]
    kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, ct.c_void_p, w.DWORD, w.DWORD, ct.c_void_p]
    kernel.CreateFileW.restype = ct.c_void_p
    kernel.DeviceIoControl.argtypes = [ct.c_void_p, w.DWORD, ct.c_void_p, w.DWORD,
                                      ct.c_void_p, w.DWORD, ct.POINTER(w.DWORD), ct.c_void_p]
    kernel.DeviceIoControl.restype = w.BOOL
    kernel.CloseHandle.argtypes = [ct.c_void_p]
    invalid = ct.c_void_p(-1).value
    report = {"schema_version": 1, "method": "Windows SetupAPI/hub read-only descriptor inventory",
              "target": "VID04b0 PID032a", "allowed_ioctl_codes": [f"0x{x:08x}" for x in sorted(ALLOWED)],
              "hubs_checked": 0, "ports_checked": 0, "matched": [], "errors": [],
              "vendor_requests_sent": False, "storage_writes": False, "driver_changes": False,
              "sources": SOURCES, "limitations": [
                  "USB descriptors establish the advertised interface, not internal debug selector semantics.",
                  "No debug transport, RAM readback, installed-image hash or recovery is verified."]}

    def ioctl(handle, code, data, size):
        if code not in ALLOWED or size > 8192 or size < len(data):
            raise ValueError("Outside bounded read-only hub allowlist")
        buffer = ct.create_string_buffer(size)
        ct.memmove(buffer, data, len(data))
        returned = w.DWORD()
        if not kernel.DeviceIoControl(handle, code, buffer, size, buffer, size, ct.byref(returned), None):
            raise ct.WinError(ct.get_last_error())
        if returned.value > size:
            raise ValueError("Hub returned an oversized result")
        return buffer.raw[:returned.value]

    devices = setup.SetupDiGetClassDevsW(ct.byref(guid), None, None, 0x12)
    if devices == invalid:
        raise ct.WinError(ct.get_last_error())
    try:
        for index in range(32):
            interface = Interface(); interface.cbSize = ct.sizeof(interface)
            if not setup.SetupDiEnumDeviceInterfaces(devices, None, ct.byref(guid), index, ct.byref(interface)):
                if ct.get_last_error() == 259:
                    break
                raise ct.WinError(ct.get_last_error())
            required = w.DWORD()
            setup.SetupDiGetDeviceInterfaceDetailW(devices, ct.byref(interface), None, 0, ct.byref(required), None)
            if not 8 <= required.value <= 8192:
                raise ValueError("Hub interface path exceeds bound")
            detail = ct.create_string_buffer(required.value)
            struct.pack_into("<I", detail, 0, 8 if ct.sizeof(ct.c_void_p) == 8 else 6)
            if not setup.SetupDiGetDeviceInterfaceDetailW(devices, ct.byref(interface), detail, required, None, None):
                raise ct.WinError(ct.get_last_error())
            path = ct.wstring_at(ct.addressof(detail) + 4)
            handle = kernel.CreateFileW(path, 0, 3, None, 3, 0, None)
            if handle == invalid:
                report["errors"].append({"hub_index": index, "open_error": ct.get_last_error()})
                continue
            try:
                node = ioctl(handle, NODE_INFO, bytes(76), 76)
                if len(node) < 7 or not 1 <= node[6] <= 127:
                    raise ValueError("Invalid USB hub port count")
                report["hubs_checked"] += 1
                for port in range(1, node[6] + 1):
                    report["ports_checked"] += 1
                    try:
                        info = ioctl(handle, CONNECTION_INFO, struct.pack("<I", port), 4096)
                    except OSError as error:
                        report["errors"].append({"hub_index": index, "port": port, "connection_error": error.winerror})
                        continue
                    if len(info) < 35:
                        raise ValueError("Truncated USB connection info")
                    if struct.unpack_from("<HH", info, 12) != (0x04b0, 0x032a):
                        continue
                    # A standard IN GET_DESCRIPTOR for configuration zero.
                    request = struct.pack("<IBBHHH", port, 0x80, 6, 0x0200, 0, 4096)
                    raw = ioctl(handle, GET_DESCRIPTOR, request, 12 + 4096)
                    if len(raw) < 21:
                        raise ValueError("Truncated USB configuration response")
                    total = struct.unpack_from("<H", raw, 14)[0]
                    configuration = parse_configuration(raw[12:12 + total])
                    report["matched"].append({"hub_index": index, "port": port,
                        "current_configuration": info[22], "speed_raw": info[23],
                        "connection_status": struct.unpack_from("<I", info, 31)[0],
                        "device_descriptor_hex": info[4:22].hex(),
                        "usb_bcd": f"0x{struct.unpack_from('<H', info, 6)[0]:04x}",
                        "advertised_configuration_count": info[21],
                        "device_bcd": f"0x{struct.unpack_from('<H', info, 16)[0]:04x}",
                        "configuration_descriptor_hex": raw[12:12 + total].hex(),
                        "configuration": configuration})
            except (OSError, ValueError) as error:
                report["errors"].append({"hub_index": index, "error": str(error)})
            finally:
                kernel.CloseHandle(handle)
        else:
            raise ValueError("USB hub enumeration exceeded32 entries")
    finally:
        setup.SetupDiDestroyDeviceInfoList(devices)
    report["status"] = "matched" if len(report["matched"]) == 1 else "no_unique_match"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker())); return
    if args.evidence is None or args.evidence.exists():
        raise ValueError("Choose a new evidence path")
    try:
        run = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--worker"],
                             capture_output=True, text=True, timeout=30)
        report = json.loads(run.stdout) if run.returncode == 0 else {"status": "worker_failed", "error": run.stderr}
    except subprocess.TimeoutExpired:
        report = {"status": "read_only_worker_timeout"}
    with args.evidence.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2); handle.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
