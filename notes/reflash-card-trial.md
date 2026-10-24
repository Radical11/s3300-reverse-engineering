# Corrected embedded-label installation trial

24 October 2026. The user explicitly requested another flash attempt with the
camera attached. Live WPD identity confirmed **COOLPIX S3300 V1.1**.

## Candidate validation

A fresh build in `derived/embedded-label-candidate-02/` reproduced the prior
candidate exactly, SHA-256:

```
a222ab366e8f328dc3a3be17b780fa42cba988d3b220487b4fb14a8016a270b4
```

The complete affected 151-block segment again passed both decoders. Exactly
five decoded label bytes change; block extents and prefix tables are retained.
The image still advertises **1.1** and preserves the product marker and download
descriptor. It contains the embedded/FAT `Welcome studio` marker, with no
creative-look or performance integration.

## USB attempt and actual blocker

After restarting the camera, both WPD root enumeration and standard PTP
GetObjectHandles showed no firmware folder. A bounded all-object metadata scan
returned 32 objects without a firmware entry. Standard WPD folder creation failed
with **0x8007001f** before a file transfer could start. A fixed existing-path
transfer attempt also failed before a data stream or commit was obtained.

The existing-path experiment was scoped to `\\FIRMWARE\\FIRMWARE.BIN`, without
arbitrary pathname input, deletion, formatting or vendor operations. Offline
analysis of the normal SendObjectInfo path at 0x80781248..0x80781440 and the
path constructor at 0x80787ac4 showed rooted-path handling, but the live WPD
attempt did not establish a working replacement route. Static listing windows
remain under ignored `derived/reflash-transfer-analysis-01/`.

The user then connected a card reader. Windows exposed removable FAT **E:**,
capacity **2,002,452,480 bytes**, matching the camera's reported card. Direct
inspection found `FIRMWARE/FIRMWARE.BIN` still present, with the exact previous
candidate hash `c34433c1849ad5e97a2115fc2a67dbecdeb94a4cbb2fdd0dd2bcd25251888312`.
Thus its absence from camera enumeration did not mean it was absent from the
filesystem. The earlier rejected USB attempts left that file unchanged.

## Card staging completed

`tools/stage_card_trial.py`:

1. Required a removable FAT drive and existing, nonredirected DCIM/FIRMWARE
   directories. Fixed drives are rejected.
2. Accepted replacement only of a known project update image.
3. Backed up the old update to the ignored local directory
   `derived/embedded-label-card-trial-01/previous-firmware.bin`, then verified
   the entire backup by exact comparison.
4. Wrote a new exclusive `FIRMWARE/S3300LAB.TMP`, flushed it, and read it back.
5. Rechecked card identity and the old file hash, then renamed the verified
   temporary file over `FIRMWARE.BIN`.
6. Flushed and read all **19,005,632 bytes** from the final card path. The bytes
   and SHA-256 exactly matched the corrected candidate above.

Evidence: `evidence/embedded-label-card-staging-2026-10-24.json`. No card
formatting or photo writes occurred. The card copy is ready for the user's
physical camera update flow. This records staging, not completed flashing.

## Camera step and unresolved acceptance

The user was instructed to safely eject E:, return the card to the powered-off
camera, use a fully charged battery, and open MENU → Setup → Firmware version.
If the normal menu offers 1.1 → 1.1, the already-authorized trial can proceed
through Yes. During updating, leave power, battery, card and controls untouched.
Completion, the English `Welcome studio` label and ordinary operation must be
observed before claiming success.

Same-version acceptance remains unverified. No version bump, marker activation,
acceptance bypass or remote flash command was introduced. If the normal menu
does not offer an update, record that outcome rather than forcing it. Recovery
remains unverified.

The staging/readback tools now use a closed two-image registry with separate
expected installed versions and exact hashes. A changed image, version, product
marker, download descriptor or checksum is rejected. The full suite passes
**122 tests**, including native look checks and eleven new card/payload guards.

[Nikon's stock update page](https://downloadcenter.nikonimglib.com/en/download/fw/60.html)
documents a card-reader staging route and camera-menu confirmation. Its supported
version transition is 1.0 → 1.1; it does not validate this experimental same-version
trial or the modified image.
