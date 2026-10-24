# First testing session

24 October 2026. Initial readiness checks completed; capture timings pending.

Update: the user prefers to continue firmware development before the manual
capture comparison. Those shooting steps are deferred, not a required action
for the next offline work. See `resource-label-candidate.md` for the first
controlled research candidate and the remaining installation dependencies.

## Completed observations

- Windows enumerated the Nikon S3300 as a present WPD device.
- A fresh bounded `GENERIC_READ` connection succeeded and closed normally.
- Identity reports Nikon Corporation / S3300 / COOLPIX S3300 V1.0 / MTP 1.00.
- The two allowed extension-introspection calls returned success. Advertised
  vendor operations remain 0x9002, 0x9003, 0x9005, 0x9006; none was executed.
- All 83 offline unit tests passed.
- In-memory reconstruction of the complete supplied v1.1 carrier matched the
  known SHA-256 and 19,005,632-byte size.

The detailed device report is local at
`evidence/wpd-device-info-2026-10-24-test.json` under the existing Git exclusion
for device-specific identity evidence. A summary without device identifiers
is committed separately. No device setting, photo, firmware, driver or memory
was written. The USB check did not measure shooting speed or validate a patch.

## First hands-on capture comparison

Disconnect USB before normal shooting. Use one stationary, well-lit scene,
fixed support, the same card, unchanged zoom/mode and flash off. Record the
camera screen and shutter-button operation with a phone so readiness changes
and presses are visible. Keep the original video timestamps and photographs.

Take five single photographs at 16 MP, waiting for readiness between shots,
then repeat five at 8 MP. Change only resolution, and show the selected setting
in the recording. Keep auto-review and every other preference the same. This
is a short exploratory batch, below the protocol's 20-trial preliminary floor.
Repeat matched batches if a useful difference appears.

The video can support visible response/ready intervals; it cannot automatically
separate autofocus, image processing and card writing. Human reaction and frame
timing uncertainty must be retained. Inspect original JPEGs for expected size,
decode integrity and any capture failures before making a speed claim.

Stock v1.0 is the current camera baseline. A future modified-v1.1 comparison
also needs matching stock-v1.1 observations once installation and restoration
are established. No custom firmware image is currently ready for camera testing.
