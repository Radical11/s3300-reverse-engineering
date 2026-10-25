# Camera verification: USB mode and the two sepia menus

25 October 2026. Camera reads use the existing Windows driver. No update,
vendor/debug request, memory read, storage write or driver replacement ran.
Raw device identifiers and original photos remain in ignored local folders.

Current result: **resource-ready passes**. The first intended-Standard pair
failure below was superseded by the explicit Standard → OK repeat described
at the end. The old observation remains preserved. Code-ready and recovery
remain blocked.

## USB now has runtime evidence

After reconnection, WPD opens the S3300 read-only and reports V1.1/MTP 1.00.
The first standard PTP inventory exposes 48 objects: two folders and 46 JPEGs.
No update object is exposed; that does not prove that a file is absent from
the physical card or identify installed flash bytes.

The new descriptor reader uses Windows' documented
[standard GET_DESCRIPTOR hub interface](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/usbioctl/ns-usbioctl-_usb_descriptor_request).
Its allowlist contains only node information, connection information and
descriptor reads. It obtains descriptors only for the matching Nikon VID/PID.
There is no interface claim, mode switch or driver replacement.

The device advertises USB 2.0 and one configuration. Current configuration 1
contains one interface, alternate 0, class 6/subclass 1/protocol 1. Its endpoints
are bulk OUT **0x01**, bulk IN **0x81** (512-byte maximum packets) and interrupt
IN **0x82** (8-byte maximum packets). Repeated descriptor bytes agree. These
packet sizes are not measured transfer throughput.

The [USB-mode map](usb-mode-contracts.md) independently traces logical
endpoints 2/3/5 to those addresses in the PTP mode-4-or-7 branch. Debug mode 6
registers different handles and descriptors. The existence of a debug
dispatcher in the image does not establish reachability through current PTP.
Mode 4 versus 7, vendor-control coexistence and an independent debug/recovery
entry remain unverified. See `evidence/camera-usb-verification-2026-10-25.json`
and `evidence/usb-mode-contracts.json`.

To repeat descriptor observation with the camera connected:

```powershell
python s3300.py camera-usb derived/my-camera-usb.json
```

This command contacts the camera for read-only descriptors. Ordinary build,
analysis, validation, guide and packaging commands do not contact it.

## The Amber label is confirmed; the old failure had the wrong menu

The user reported these six options: Soft, Nostalgic sepia, High-contrast
monochrome, High key, Low key and Selective color. Those are Special effects,
documented separately from Auto mode's Color options in Nikon's
[S3300 reference manual, pages 47 and E29](https://download.nikonimglib.com/archive2/vu9iI00riFfv01k96Qt63uLVv147/S3300RM_EU%28En%2901.pdf).
The user also confirmed Welcome studio.

After selecting **Auto mode → MENU → Color options**, the user explicitly
confirmed the fourth choice is **Amber**. This supersedes the earlier
menu-label failure; the append-only ledger retains both observations.
No additional firmware update was required.

The original English table itself has separate records: ID **563**, Sepia,
at **0x8036e47a**, and ID **1154**, Nostalgic sepia, at **0x803716fa**.
Amber modifies only the first label. The source-bound lookup analysis and the
corrected screen observation now agree. Version/marker observations still do
not identify every installed byte.

## First explicit Auto-mode pair: both photographs have Amber tint

The user completed a requested Standard-then-Amber photo pair and reported no
failure in the full restart, remembered-Amber and playback checks. Inventory
then exposed two new JPEGs. Both were read twice using standard PTP GetObject,
compared byte-for-byte and checked after local copying.

| File | Intended selection in requested protocol | SHA-256 | Unclipped Cb / Cr means |
| --- | --- | --- | --- |
| DSCN1186.JPG | Standard color | 4275439b2659df7467864fdd6830cf2d005c42b5456ead31869723920acf12e3 | 109.9994 / 149.9986 |
| DSCN1187.JPG | Amber | e4e6ddd6e7fe8ba402d94e11c3456408e5eb6dbc7162e2148b0127a1f1254dfe | 110.0000 / 149.9998 |

Both images are 4608×3456. Chroma deviation is very small in millions of
unclipped pixels, corroborating the Amber constant tint in both files.
Consequently the intended Standard bypass check **failed in this pair**.
The exact UI commitment for the first selection was not independently
observed; this is not assigned a firmware cause. A repeat was requested with
explicit **Standard color → OK**, a preview-colour observation and one photo.

The new Auto-mode setup is more specific than the earlier photo provenance.
Earlier pixel statistics remain valid, while the earlier assumed menu route is
superseded. Current acceptance follows the latest ledger, not this historical
pair alone. No speed, energy or image-quality improvement is inferred.

## Explicit Standard repeat passes

The user reports normal Standard colour after the explicit apply/preview
instruction. A third new file, **DSCN1188.JPG**, was read twice, compared and
verified after local copying. SHA-256:

`da7126e5d8c50ad726ed0ece80e2b8ca1688f7f4bbd82fec59d57720fb38eda9`

Its unclipped Cb/Cr means are **134.13 / 126.91**, with deviations **14.79 /
9.47** across more than 14.6 million pixels, corroborating varied colour rather
than constant Amber tint. The failed first pair is superseded without deleting
its record or claiming a proven cause. Current menu, saved-photo effect,
Standard bypass, restart, remembered selection and playback checks all pass.
Pixel evidence is direct; menu/restart/playback observations remain user reports.

The intended candidate association remains SHA-256
`d801708b06abbaece3974b2ae0cb9c55ce4154fffc0c132e00b35564ec86ce28`;
the exact installed image hash remains unknown. The last reported selection is
Auto mode, Standard color. See `evidence/amber-auto-verification-2026-10-25.json`
and the current readiness ledger. Normal rollback, unbootable recovery, safe
code integration and any performance improvement remain unverified.
