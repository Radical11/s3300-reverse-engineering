# S3300 developer handbook

This handbook explains how to understand, change and test the S3300 firmware
with this repository. Start with the first two chapters, then choose a tutorial.
Every example starts from the preserved original v1.1 update; existing working
candidates and private photos stay separate.

| Chapter | Use it for |
| --- | --- |
| [Start here](01-start-here.md) | Readiness, vocabulary, supported changes and the first ten minutes |
| [Install and reproduce](02-setup.md) | Python, original input, portable analysis tools and a fresh build |
| [Architecture and evidence](03-architecture.md) | Address spaces, code/resources, analysis scope and confidence |
| [Find a feature](04-find-a-feature.md) | Search, cross-references, pseudocode and interface research |
| [Edit resources](05-resource-tutorials.md) | Strings, indexed artwork, startup art and fixed-size plans |
| [A saved-photo experiment](06-amber.md) | Rebuild and test the existing Amber parameter change |
| [Write a module](07-sdk.md) | Target compilation, memory ownership and executable integration gates |
| [Build and validate](08-build-and-package.md) | Budgets, independent checking and local trial packages |
| [Test on the camera](09-camera-tests.md) | Exact-build observations, photo checks and matched timing |
| [Recovery and troubleshooting](10-recovery-and-troubleshooting.md) | Rollback versus recovery, failures and unresolved contracts |
| [Interface reference](11-interface-reference.md) | A concise index of recovered interfaces and their remaining gaps |

Build the offline searchable edition from the repository root:

```powershell
python s3300.py guide derived/development-guide
```

Open the generated `index.html` in a browser. It needs no web server or network
connection and never runs firmware commands. Choose a new output directory for
each rebuild. The edition records the hashes of the source chapters and the
readiness evidence it included. Rebuild after recording new camera results.

For interactive exploration of the existing workspace, run
`python s3300.py browse` and open its localhost address. The local workbench
searches native functions and interface contracts, follows static calls and
shows research reports and readiness dependencies. It requires no new unpacking
and exposes no camera operations. See [Find a feature](04-find-a-feature.md).

For native function lookup after a completed application export:

```powershell
python s3300.py native-index derived/native-analysis-complete derived/my-native-index
python s3300.py pseudocode --database derived/my-native-index/native.sqlite --address 0x80737664
```

The current camera evidence confirms Amber in Auto mode's Color options,
its tint in saved photos and normal Standard colour after explicitly applying
that setting. Restart/playback/remembered-selection checks pass by user report.
The resource-ready milestone passes. The earlier Nostalgic sepia observation
was from the separate Special effects menu; its failed label record is retained
and superseded. These observations do not establish executable recovery or
code-ready status. Read the current readiness record before choosing a trial.

The 25 October contract follow-ups add the English label lookup, shared frame
geometry and temporary-buffer lifecycle, executable memory exclusions, and USB
debug state/dispatch. The later USB mode map correlates the live PTP endpoints
with a different registration from debug mode. Find these reusable research
results through the interface reference and recovery chapter. Executable and
recovery gates remain blocked.

The next contract pass traces the asynchronous saved-JPEG pipeline and its
consuming segment writer, path-specific cache/DMA handoffs, the tiny loader's
missing ROM dependency, and PTP vendor registrations. Recheck those maps with
`research-map` as described in the interface chapter. The feature dependency
ledger in `firmware/sdk/dependencies.json` reports which contracts block each
kind of modification; it cannot approve camera trials.

The guide explains both completed capabilities and research interfaces. It is
not permission to call every address in the reference. A readable decompiler
listing, successful host test or user-observed label does not establish that an
arbitrary firmware patch is recoverable.
