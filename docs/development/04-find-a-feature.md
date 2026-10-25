# Find a feature and understand its contract

Start from visible behavior rather than changing a nearby-looking constant.
For example, the word Gamma can belong to a display path, a saved-image path,
a packed resource converter or a debug interface. The same name does not make
those objects interchangeable.

## Explore in the local workbench

```powershell
python s3300.py browse
```

Open the localhost address printed in the terminal. The workbench provides
readiness and feature dependencies, hardware/stock-limit distinctions, searchable interface contracts, native
function/pseudocode search, callers/callees, unresolved indirect transfers and
the source-bound research reports. Searching an exact entry such as
`0x80008f80` shows that function and any matching recovered interface contract.
Choose an executable in the image selector first. Application, updater and
loader addresses can overlap; callers and contracts stay within that namespace.
Packed carriers explicitly show inventory-only coverage rather than invented
disassembly of compressed bytes. Use `artifact-function --image IMAGE --address
ADDRESS` for the same lookup from the terminal.
Generated Ghidra signatures can conflict with the pseudocode; the display
labels them as inferred and keeps recovered argument/ownership constraints
beside them.

The browser reads existing analysis without extracting or decompiling again.
It verifies the native database against its retained manifest, rejects changes
to that database during a session, and never offers a camera command, firmware
upload or update action. Vendor-derived pseudocode remains local. Interface
entries are research contracts; a blocked card is not an SDK function pointer.
Press Ctrl+C in the terminal to stop the service. `browse --check` checks its
datasets without starting it, and `--database PATH` selects another retained
source-compatible native index. Without a native index, readiness and the
interface/research views remain available.

## Search from a symptom or resource

```powershell
python s3300.py search 'Welcome screen'
python s3300.py atlas --search GAMMALUT
python s3300.py atlas --subsystem ui_controls --limit 20
python s3300.py atlas --address 0x80737664
python s3300.py atlas --address 0x80737664 --assembly
python s3300.py interface --search settings
python s3300.py pseudocode --address 0x80737664
python s3300.py pseudocode --search Capture --limit 10
```

The basic workspace search covers text resources and address/symbol metadata.
The atlas additionally supplies incoming/outgoing transfer candidates,
diagnostic associations and raw pointer candidates. Its default is a bounded
result set; request additional results deliberately rather than interpreting
the first page as the complete program.

## Follow data and effects

Record the entry, arguments and returns. Check every pointer's region, domain,
length, ownership and lifetime. Follow a state write to the consumer that
actually uses it. Record synchronization, blocking, allocation, possible
failure, shared users and persistent side effects. Keep addresses and exact
instruction evidence alongside any proposed meaningful name.

For command 15, the wrapper is not simply an enqueue: ordinary contexts retain
a copied payload synchronously, while context `0x90` queues a separately copied
command. An adapter that assumes the same lifetime for both has not met the
contract. For GPIO, the monitor command called a getter configures state before
reading; its name does not establish a passive operation.

## Consult native pseudocode without trusting it blindly

Use the retained native-analysis database and per-function results. A seeded
function boundary is a caller assertion derived from authenticated metadata,
not independent function discovery. Inspect branches and delay slots in the
raw listing, compare key bytes against the authenticated image, and preserve
unresolved indirect transfers. Mark invented type names as analyst labels.

The `pseudocode` command reads the retained native index without launching
camera code. Choose `--database PATH` when using a separately built index.
An address with a failed decompilation still needs its retained error and raw
listing; do not treat an empty result as proof that the function does nothing.

For a timeout, `python s3300.py native-retry derived/native-analysis-complete
--address 0x80248bf4 --timeout 120` preserves the original failure and writes
a separate retry dossier. Use an address that actually failed and a fresh retry
log; do not repeat successful analyses. Rebuild the native index into a new
directory to include successful retry overlays. Engine normalization/type
errors need a specific investigation rather than repeated identical calls.

Never turn a decompiler's guessed pointer or array size directly into an SDK
header. Prove the offset, field width, bounds and lifecycle in the actual
instructions and callers first. A function that happens to decompile may still
have missing code or a wrong boundary.

## Save a reusable interface record

Each interface needs an identity and scope, original/analysis hashes, entry and
mode, provenance, arguments/returns, structure fields, bounds, ownership,
effects, synchronization, error cases, reviewed callers and unresolved items.
Record contradictory evidence as well. The interface lookup and readiness
commands should direct the next developer to the same retained sources.

A good research result can be that an interface is not ready to call. That
result prevents future experiments from repeating a known unsafe assumption.
