# The ns2jb exploit chain, mapped against the code

This is a reading of the capture (upstream commit `95f5525`), organized as the
four stages the pipeline actually runs. Every claim below points at a file in
this repo; the blog prose (`docs/blog-capture.md`) is the narrative, this is the
code.

## Stage 0 — Bootstrap: SmileBASIC userspace to RPC host

**File: `bootstrap.bas`** — the only file a human ever types into the console.

- `RUN` prints `DIST BOOT READY 1015` and ends. `START(...)` is the real entry,
  invoked from Direct mode with the host IP octets and four u64 words the
  computer prints.
- The `REMOVE NSR,&H60000000,&H3FFFFFFF` command is issued **once from Direct
  mode after RUN**. That is the bug trigger: the interpreter's bounds check
  `position + count <= array.length` passes because the signed 32-bit sum wraps
  negative, so the left-shift `memmove` pulls the 8 bytes before the backing
  array — which contain the array's own pointer — into `R[0]`. The expected
  "Out of memory" error is harmless; the corruption already happened.
- After that, reads/writes through `R[0]`'s substring aliases reach all of
  SmileBASIC memory. `W$(A,N)` (arbitrary read) and `PUT O,V` (arbitrary write)
  wrap that primitive.
- `BOOT()` does not trust addresses from anywhere: it scans memory for a
  fingerprint (`L#==5 && PTR(V#-&H9DB49C,4096)`), then pins the found bases with
  a set of hard-coded hash checks (`HASH#(...) != <constant>` — fails 13..28).
  Those constants are this firmware version's (SmileBASIC 4.4.9, 23.0.1) code
  fingerprints; they fail loudly on any other version.
- `RAW#(V$)` is the call primitive: it writes four argument words to fixed
  offsets inside a string backing buffer, then places a pointer chain so the
  interpreter's next native call lands on a chosen address — a one-gadget call
  with four u64 arguments. `CALL#(F,A,B,C,E)` is the friendly wrapper.
- `START` uses that to open a TCP socket (`fd`), connect back to the computer on
  port 39380, send a 128-byte hello (the base addresses the harness needs), and
  enter `RPC()` — a loop that executes u64-opcode requests the host sends over
  the socket and returns results. From here, **the computer has arbitrary
  userspace read/write/call in SmileBASIC**, and everything else runs from Node.

## Stage 1 — FS arbitrary read/write

**Files: `engine/switch2/memory/normalized-path.cjs`, `fs-memory-control.cjs`,
`cache-address-plan.cjs`, `signed-cache-plan.cjs`, `acquire.cjs`**

- The FS bug: `IFileSystem.GetEntryType` normalizes the requested path. Paths
  containing a parent-directory component with a backslash (`/..\`) take a
  helper that allocates a **0x301-byte** heap buffer and copies the (already
  normalized, attacker-controlled-length) path in. Longer paths overflow it.
- `normalizedPath(prefix, length)` builds those overflow paths deterministically
  — always already-normalized (`/AAAA...` runs), length exactly tuned.
- The write target is a `BufferedStorage` cache entry: with its dirty bit set,
  FS reads/writes the file through the entry's backing-buffer pointer. Overwrite
  the pointer and reads/writes become arbitrary.
- The engine models this as a **"signed-one-shot" cache header** plan
  (`fs-memory-control.cjs: encoding === 'signed-one-shot'`): each read/write
  retargets the window; the planner (`signed-cache-plan.cjs`) computes the
  header bytes so a target address lands inside the storage-size window,
  aligned to the bucket period (`cacheAddress.bucketPeriod`, 0x500000 by
  default). This is the stability trick from the blog's footnote 4 — mutate one
  cache entry's metadata instead of repeating the overflow per access.
- Qualification is strict: `acquire.cjs` proves read, write, **and restoration**
  before anything else runs, and every run writes a JSON proof into `runs/`.

## Stage 2 — FullPermission and the dumps

- With FS ARW, the code scans the connection objects and sets SmileBASIC's
  **saved process ID to 1**. PID ≤ 6 makes the FS permission check treat the
  caller as a built-in sysmodule; the default mask `0x8000000000000000` gives
  FullPermission. (`fs-memory-control.cjs` talks about "root" commands for
  everything obtained this way.)
- That is what turns the SmileBASIC session into something that can read
  ordinary sysmodule code and internal storage — the dumps that stage 3's
  analysis was built on.

## Stage 3 — Native code execution as `ro`

**Files: `engine/switch2/ro/*`, payload in `engine/switch2/ro/payload/`**

The FS-serves-decrypted-code angle: the loader (`ldr`) opens ExeFS through FS
and verifies two signatures (NPDM signed by Nintendo, NCA header signed by the
developer) whose hash chain fixes the executable. But the hash the loader
checks is the one **FS reported** for the filesystem — and FS is compromised.
So the engine swaps the domain-table entry: the loader's ExeFS connection is
repointed at a temporary filesystem object that serves the original `main.npdm`
plus an arbitrary `main` (`ro/copy-loader-root.cjs`, `ro/objects.cjs`). A second
write swaps the refcounts back so FS doesn't crash. Timing is controlled by
replacing the FS-side wait handle for the loader connection with an event handle
SmileBASIC owns (`ro/prepare-event.cjs`).

The launched program is a 4757-byte NSO (program ID `0x0400000000000037`, `ro`'s
NPDM — hence `SetProcessMemoryPermission`/`MapProcessCodeMemory`/
`MapProcessMemory` SVCs are available to it):

- `payload/main.c` — a freestanding IPC server, no heap, no absolute pointers.
  Registers `ro:1` (space 2) and `ro:dmnt` (space 1) with SM, polls both ports
  and up to 4 sessions, and dispatches `SFCI`-shaped requests. Command
  `0x524f0001` is the handshake: it returns a magic (`NS2ROEXE`), a reply that
  XORs the request's first word with a constant, the caller's PID/TID, a tick,
  and the registration results. Everything else forwards to `process_request`.
- `payload/process.c` — the bounded probe set, all through a **real process
  handle transferred by IPC** (never self-SVC abuse):
  - `0x524f0010` query — memory info of the target plus free-address search
  - `0x524f0014` **patch** — map one page of the target via `MapProcessMemory`
    into a readable alias in RO, verify the exact expected 16 bytes, write 16
    replacement bytes, `dc cvau` + `ic ivau` (`publish_code`), verify readback,
    unmap
  - `0x524f0011`/`0x524f0016` **read** — copy ≤128 bytes / ≤4 MiB out through
    the same temporary alias
  - `0x524f0012`/`0x524f0013` map/unmap one caller-owned RW page as executable
  - `0x524f0015` toggle the read bit on native FS executable pages
  Every command re-checks the target's memory type/permissions/attributes
  before acting. The payload is a scoped memory tool, not a shellcode launcher.
- `payload/start.S` provides `_start` and the raw SVC wrappers
  (`connect_port`, `send_request`, `wait_handles`, `reply_receive`,
  `accept_session`, `process_id`, `thread_id`, `system_tick`, and the map
  functions in `process.c`'s externs).
- The patched instruction pattern: `fs-execute.cjs` pins the FS
  `GetEventHandle` entry by its 16-byte prologue
  `7f2303d5 ff8300d1 fd7b01a9 fd430091` before patching, and the replacement
  stub is generated (`returnCode(nonce)`): `nop; movz w0, #nonce; movk w0,
  #nonce>>16; ret` — the demo's proof of execution is the notifier method
  returning a **fresh, instruction-generated nonce** rather than a handle.
- `engine/switch2/pipeline.cjs` is the fixed sequence: console check → FS
  acquisition → RO payload install/gate/launch → instruction challenges → FS
  demo → cleanup, with every stage journalled to `pipeline.json` and proofs to
  `runs/`. Failure paths restore or explicitly abandon (`acquisition.retire()` /
  `acquisition.abandon()`); the README's "restart the console" rule exists
  because later failures can leave native state only a reboot clears.

## Host requirements

Node 22+ on macOS/Linux per upstream README (the RPC host), SmileBASIC 4.4.9
with ≥20 MiB free save space, console and computer on the same network, port
39380 open. `run.cjs` selects the reachable address; `test.cjs` runs the
host-side unit checks without hardware.

## What is deliberately out of scope here

- No persistence: a reboot restores stock RO and clears every write. Upstream
  ships a demo, not CFW.
- No WebKit path: the blog's Codex WebKit n-day branch was abandoned; this
  package is the SmileBASIC → FS → RO chain only.
- Nothing here targets anything but this console/firmware/game combination;
  see `AGENTS.md` for this repo's rules.

## Host portability boundary

The Switch connection itself is not POSIX-specific. `run.cjs` uses
`node:net` TCP on port 39380 and Node's normal network-interface enumeration.

The concrete Windows blocker in the captured host is the private control
channel used by the retained FS-memory endpoint:

- `memory/run-control.cjs` hard-coded `/tmp/ns2-`;
- `memory/fs-memory-control.cjs` created `memory.sock`, listened on that
  filesystem path, and applied POSIX `chmod(0600)`;
- `tools/endpoint.cjs` reconnects to the resulting endpoint through
  `net.createConnection(path)`.

The Windows-port layer keeps that interface shape intact. The server/client
code still passes a single IPC path string, but `shared/local-ipc.cjs`
selects a Unix-domain socket on Unix and a Windows named-pipe path on Windows.
This avoids changing the exploit protocol or the internal request format.

Security boundary: the Windows named pipe is local IPC and receives a
cryptographically random per-run name. It is not exposed on the LAN. This is
not a claim of a new authentication protocol; callers still depend on the
local host account/security boundary just as the Unix implementation depended
on filesystem permissions.

Remaining Windows-specific caution: Node's child-process `SIGTERM`/
`SIGKILL` handling on Windows is abrupt, not POSIX signal delivery. The
normal success path does not depend on changing exploit behavior, but abort
and timeout cleanup must be treated conservatively until hardware-tested.
