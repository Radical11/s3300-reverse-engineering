# New S3300 sample check

23 October 2026. Four new camera files, DSCN1161 through DSCN1164, were copied
from `S3300/DCIM/100NIKON` to `samples/new-originals/`. Source photos were not
edited or deleted. Their hashes and EXIF values are in that folder's
`metadata.json`; previews are in `samples/previews/`.

All four are 4608x3456 COOLPIX S3300 JPEGs reporting firmware V1.0. They all
record **0 EV exposure compensation**, f/3.5, and flash not fired.

| File | ISO | Exposure time |
| --- | ---: | ---: |
| DSCN1161 | 800 | 0.4 s |
| DSCN1162 | 800 | 0.4 s |
| DSCN1163 | 800 | 0.25 s |
| DSCN1164 | 400 | about 1/13 s |

Visual inspection shows pronounced softness/blur, especially in the second
portrait, and bright lamp/highlight areas. Face-detail crops show directional
smearing/doubled features consistent with motion during the long exposure.
Exact contributions from camera shake, subject movement, focus and in-camera
noise reduction cannot be separated from these JPEGs alone.

These are a better settings baseline than the earlier -1.3 EV samples, but the
scenes differ, so they are not a controlled before/after exposure experiment.
Their main limitation is not a need for a blanket brightness increase. A
useful next capture comparison holds the camera and subject still or adds
light, then compares detail/noise. Any future firmware exposure policy would
need to balance blur from long exposures against noise from higher gain;
the relevant firmware control has not yet been located.
