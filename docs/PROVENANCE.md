# Provenance — what this repository is and where it came from

## Upstream

- **Upstream repository:** https://gitlab.com/pepsipu/ns2jb (author: pepsipu)
- **Companion write-up:** https://pepsipu.com/blog/2026-10-switch2-jailbreak-ns2jb/ (October 18, 2026)
- **Upstream commit captured:** `95f5525089273c5fce0b95047f3600f8442e96ae` ("clarify"), the tip of `main` on 2026-10-22
- **Upstream history:** 3 commits — `e4ded17` "Import tested Switch 2 distribution", `4f03533` "add attribution", `95f5525` "clarify"

The full upstream history, commit messages, and `SHA256SUMS` are preserved in
this repository. `origin` still points at the GitLab upstream; `github` and
`codeberg` are the working remotes for this rework.

## Fork / rework

- **GitHub mirror (working):** https://github.com/mhzsajan/ns2jb
- **Codeberg mirror (working):** https://codeberg.org/mhzsajan/ns2jb

## Capture verification

The upstream README claims `engine/switch2/ro/payload/main` (the native NSO
payload) can be rebuilt byte-identically from `main.c`, `process.c`, and
`start.S` with Zig 0.15.2. We verified that claim at capture time:

```
node engine/build-payload.cjs --check --zig <path to zig 0.15.2>
{"bytes":4757,"sha256":"d590cbfc5d9152c24d5a36f083f8470a2f3164be6b78130129d44132b939701a","matched":true}
```

- Zig 0.15.2, Windows x86-64 build (`zig-x86_64-windows-0.15.2`)
- `matched: true` — the rebuilt NSO image equals the shipped `main` byte-for-byte
- `payloadBytes: 4757`, SHA-256 as above (matches `engine/switch2/ro/payload/manifest.json`)

This is a stronger statement than trusting `SHA256SUMS`: the shipped binary is
reproducible from the shipped source, on an independent machine.

## Scope of the rework

Nothing in `engine/` has been changed in the capture commit. The rework so far
is documentation and analysis:

- `docs/PROVENANCE.md` — this file
- `docs/ANALYSIS.md` — the exploit chain mapped against the actual code
- `docs/blog-capture.md` — captured copy of the companion write-up

Later rework commits will say explicitly which `engine/` files they touch and why.

## Hardware claim status

The upstream author reports the demo was physically tested on a Switch 2,
system software 23.0.1, SmileBASIC 4.4.9, on 2026-10-21 (third fresh boot; the
first two attempts stopped at validation checks and cleaned up). We have **not**
re-run anything on hardware; every local check here is host-side: the
reproducible-build check, and unit-level checks under `test.cjs`.

## 2026-10-23 — Windows host portability rework

This fork now intentionally diverges from the captured upstream host engine in
a narrow portability layer. The following host-side files are changed or added:

- `engine/shared/local-ipc.cjs` — cross-platform temporary-directory and local
  IPC endpoint helpers;
- `engine/switch2/memory/run-control.cjs` — uses the host OS temp directory
  instead of hard-coded `/tmp`;
- `engine/switch2/memory/fs-memory-control.cjs` — uses Unix-domain sockets on
  Unix and per-run random Windows named pipes on Windows;
- `test.cjs` — covers both IPC path formats and portable temp directories.

The Switch-facing TCP protocol, native helper source/binary, payload manifest,
exploit constants and execution sequence were not changed by this port.

**Verification status:** VERIFIED ON OWNED HARDWARE on 2026-10-23.

The Windows host-port completed the published ns2jb path end-to-end against an
owned Switch 2 using system software **23.0.1**, SmileBASIC **4.4.9**, and
Node.js **24.x** on the Windows host. The observed behavior matched the previous
host path, including the known crash after the successful run. This verifies
the Windows host portability layer in a real console run; it does not turn the
post-run crash into a clean-shutdown result.

The tested branch was `windows-host-port`. The branch head at the time the
result was reported was `998c9660fc8e167af047af3d473a537af12373c8`; the
exact local checkout hash was not separately captured during the hardware run.
`engine/switch2/ro/payload/` was not modified, so the native payload
reproducibility anchor remains unchanged.
