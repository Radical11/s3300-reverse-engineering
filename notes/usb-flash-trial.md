# USB staging and first experimental update

24 October 2026. User-authorized experimental trial. Last observed device
identity before updating: `COOLPIX S3300 V1.0`. The user subsequently reported
`COOLPIX S3300 Ver. 1.1` but no `Welcome studio` label. Thus the version transition
is reported complete; custom resource activation is not confirmed. See the
follow-up in [embedded resources](embedded-resources.md).

## What actually worked

Explorer exposed an empty S3300 namespace, but direct Windows WPD found one
card storage object: capacity 2,002,452,480 bytes, free 1,897,562,112 bytes,
access capability 0 (read/write). Initial root inventory contained only DCIM.

`tools/stage_wpd_trial.py --stage` independently validated the exact local
candidate, opened only the matched Nikon VID04b0/PID032a device, created the
firmware folder and transferred the file through standard WPD object APIs.
The stream accepted every byte and committed. No existing files were replaced.
The camera normalized the names to `FIRMWARE/FIRMWARE.BIN`.

Windows WPD subsequently returned `0x80070032` (request not supported) for the
binary's Properties.GetValues and Resources.GetStream. Five read-only diagnostic
reports preserve the narrowing of that failure; none retried the write. Root
enumeration still worked, and free space had fallen to 1,878,491,136 bytes.
An unsupported WPD metadata query did not establish a failed file transfer.

`tools/read_ptp_staged.py` then used the same installed driver and a read-only
WPD connection to issue only these standard PTP operations:

| Operation | Code | Observed result |
| --- | --- | --- |
| GetStorageIDs | 0x1004 | One storage, 0x00010001 |
| GetObjectHandles | 0x1007 | Root and firmware-folder children enumerated |
| GetObjectInfo | 0x1008 | FIRMWARE folder and FIRMWARE.BIN metadata read |
| GetObject | 0x1009 | All 19,005,632 bytes downloaded |

All seven PTP transactions ended with response `0x2001` (OK). The binary's
parent matched the verified root firmware folder. Its complete contents matched
the local candidate byte-for-byte and by SHA-256:

```
c34433c1849ad5e97a2115fc2a67dbecdeb94a4cbb2fdd0dd2bcd25251888312
```

Evidence: `evidence/wpd-trial-stage-2026-10-24.json`,
`evidence/wpd-trial-readback-05-2026-10-24.json`, and
`evidence/wpd-ptp-readback-2026-10-24.json`. Their installation flags describe
the time of those probes, before the user operated the update menu.

## Current physical step

The user now reports v1.1 and ordinary menu access, but the intended English
label is absent. Version 1.1 alone cannot establish custom resource activation.
Playback and saved-photo testing remain unobserved. During any future update,
leave power, battery, card and controls untouched until completion.

The candidate only changes the English `Welcome screen` label and the additive
checksum (six changed bytes). It has no new shooting mode or speed optimization.
Firmware acceptance, runtime activation and restoration remain distinct claims.
No remote execution/update command, unknown vendor opcode, formatting, photo
deletion, driver change or hardware modification was performed by these tools.

## Reproduce the read-only check

With the device connected normally and the independently checked local candidate
still present, use a new output filename:

```powershell
python tools/read_ptp_staged.py --evidence evidence/another-ptp-readback.json
```

Do not run device tools during an update. Staging refuses to overwrite an
existing firmware.bin or write into a directory whose entries cannot be
identified. Readback can be repeated without staging again. The read-only PTP
fallback uses explicit opcode/parameter-count allowlists and bounded payloads;
it exposes no arbitrary-command option.

## Primary references

- [Microsoft WPD MTP data-read command](https://learn.microsoft.com/en-us/windows/win32/wpd_sdk/wpd-command-mtp-ext-execute-command-with-data-to-read).
- [Microsoft Windows SDK WpdMtpExtensions.h](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/WpdMtpExtensions.h).
- [Microsoft Windows SDK PortableDevice.h](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/PortableDevice.h).
- [libgphoto2 PTP operation and response definitions](https://github.com/gphoto/libgphoto2/blob/master/camlibs/ptp2/ptp.h).
- [Nikon S3300 v1.1 update guide](https://nikonimglib.com/europe/Firmware/S3300/v1.1/En/ecpx_win_en.html).
  Its stock procedure covers the folder layout and physical update controls;
  it does not validate the modified image or our USB staging route.
