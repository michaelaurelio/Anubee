# Probe specs: one selector grammar for every engine

`anubee` has five engines that select targets: `funcs`, `correlate`, `syscalls`, `dump`, `mod`.
All five read the same spec grammar, via `-e SPEC` (inline, repeatable) and `-F FILE` (spec
file, repeatable). A spec file can mix targets for several engines. Each engine reads only
the lines it understands and skips the rest. That's what lets one `.spec` file drive a whole
`anubee trace` capture across engines.

For per-engine flags (`-p`, `-P`, `-o`, ...) see `README.md` / `DOCUMENTATION.md`.

## Grammar

```
[KIND:]TARGET[(ARGTYPES)][>RETTYPE]
```

| Part | Meaning |
|---|---|
| `KIND:` | Which engine this line is for. Omit it for a uprobe target. |
| `TARGET` | What to match: exact name, `MODULE!FUNC`, a glob, or a `/regex/`. Rules differ per kind, see below. |
| `(ARGTYPES)` | Optional, `funcs:`/unprefixed lines only. Comma-separated typed arguments to decode. |
| `>RETTYPE` | Optional, `funcs:`/unprefixed lines only. Decode the return value. |

A leading `!` on the target (`syscall:!NAME`, `lib:!PATTERN`) means deny instead of allow.
Only those two kinds support it.

### Kinds

| Prefix | Default? | Selects | Consumed by |
|---|---|---|---|
| `funcs:` (or no prefix) | yes | a uprobe target: `MODULE!FUNC[@OFFSET][(ARGTYPES)][>RETTYPE]` | `funcs`, `correlate` |
| `syscall:[!]NAME` or `syscall:LIBPATTERN!NAME` | | one syscall name, allow or deny; optionally scoped to a library | `syscalls` |
| `lib:[!]PATTERN` | | a library selector (substring or glob, repeatable/OR'd) | `syscalls`, `dump` |
| `mod:NAME` | | an analyzer name | `mod` |

Every unprefixed line is a `funcs:` line. That's the default kind, so old spec files still
parse without changes.

### Argtypes (funcs-side only)

| Code | Type | Decoded as |
|---|---|---|
| `S` | string | the pointed-to C string |
| `V` | value/raw | raw integer |
| `F` | fd | resolved to its path |
| `A` | sockaddr | `ip:port` |

A return type after `>` is `S` or `V` only. No `()` and no `>RETTYPE` means an entry-only
probe with no argument decoding.

### `@OFFSET`

Skips symbol lookup and probes a raw file offset (from a disassembly, not a `readelf`/`nm`
vaddr). This is the only way to reach a `static` function missing from `.dynsym`:

```
funcs -e 'libfoo.so@0x4120(S)>V'
```

## Matching rules

Matching differs by kind, and for `funcs:`/unprefixed lines it also differs by which side of
`!` you're on. This is the part most likely to trip you up:

- **`funcs:`/unprefixed module side** (before `!`, e.g. `libc.so!getenv`): exact/substring,
  glob (`*`, `?`, `[`, via `fnmatch`), or `/regex/`. All three do real bulk matching: one line
  can follow a symbol across every module whose basename matches.
- **`funcs:`/unprefixed func side** (after `!`): exact match or `/regex/` only. Glob does NOT
  bulk-match here. `sentinel_check_*` is treated as a literal name and fails to resolve.
  `/regex/` is the only way to bulk-select functions.
- **`lib:` pattern** (the `syscalls`/`dump` library selector): substring or glob only, no
  `/regex/`. This is a separate matcher from the funcs-side module match above, even though
  the syntax looks similar.

```
funcs -e 'libc.so!/^__system_property_/'      # bulk: every libc symbol with that prefix
funcs -e 'lib*.so!getenv(S)>V'                # bulk: getenv across every lib*.so module
funcs -e 'libc.so!getenv_*'                   # wrong: glob on func side resolves nothing
```

## Per-syscall library binding

`syscall:` and `lib:` are otherwise independent, global selectors: `syscall:` picks which
syscalls, `lib:`/`-l` picks which libraries, and every selected syscall is captured from every
selected library. `syscall:LIBPATTERN!NAME` binds a library specifically to one syscall, so
different syscalls can come from different libraries in the same run:

```
anubee syscalls -P com.example.app -e 'syscall:libc.so!openat' -e 'syscall:libfoo.so!openat' \
                                  -e 'syscall:libsentinel.so!read'
```

Here `openat` is captured only when issued from `libc.so` or `libfoo.so` (multiple
`LIBPATTERN!NAME` lines for the same `NAME` OR together), and `read` only from `libsentinel.so`.
`LIBPATTERN` has the same matching power as a standalone `lib:` pattern (substring/glob, no
`/regex/`) and splits on the first `!`, same rule as `funcs:`'s `MODULE!FUNC`. So
`syscall:libc.so!openat` visually parallels `funcs:libc.so!open`.

This is enforced in userspace, not the kernel: `anubee syscalls` has no in-kernel notion of
"which library issued which syscall," so a scoped run still captures the broader union
in-kernel (every scoped syscall, from every scoped library) and then silently drops any
captured event whose own syscall's scope isn't satisfied, using the same stack-based
issuer check the kernel itself uses. No observable difference from a purely in-kernel filter,
just noted here in case you're reasoning about overhead on a very hot syscall.

Restrictions, enforced as hard errors (not a warning) at startup:
- **Deny can't combine with scoping.** `syscall:!libc.so!openat` is rejected: "capture
  `openat` from everywhere except `libc.so`" isn't expressible.
- **A syscall name can't be both scoped and unscoped in the same run.** Mixing
  `syscall:libc.so!openat` with a bare `syscall:openat` line, or with `-s openat`/`-x openat`,
  is rejected rather than silently picking one.

Works via both `-e` and `-F` (unlike the `-e`-only default-kind behavior below). Note, though,
that `-e`'s bare/no-prefix shortcut does **not** apply to the scoped form: a bare
`-e 'libc.so!openat'` (no `syscall:` prefix) is treated as a `funcs:` uprobe target, not a
scoped syscall, because it already looks funcs-shaped (contains `!`). Use the explicit
`syscall:` prefix when adding a `LIBPATTERN!` binding.

## Spec files (`-F FILE`)

One spec per line. `#` starts a comment. Blank lines are skipped. A malformed line aborts
loading the whole file (not a silent skip), so a typo in a shared spec file is never just
dropped unnoticed. Lines are read up to 512 characters. Each engine caps specs at 64 total
(`-e` plus every `-F` file combined); a warning prints if a file has more. Source:
`src/common/probe_spec_loader.c`.

`-e` and `-F` layer, not replace. Inline probes add to whatever a spec file already loaded:

```
funcs -P com.example.app -F myapp.spec -e 'libc.so!/^encrypt/'
```

### One file, several engines

Each engine reads only the kind lines it understands, so one mixed file can drive several
engines at once:

```
# myapp.spec
libc.so!fopen(S,S)>V          # funcs: (default kind), read by funcs/correlate
syscall:openat                # read by syscalls
lib:libfoo.so                 # read by syscalls (selector) and dump (pattern)
```

```
anubee funcs    -P com.example.app -F myapp.spec -o funcs.jsonl      # reads the fopen line
anubee syscalls -P com.example.app -F myapp.spec -o syscalls.jsonl   # reads syscall:/lib: lines
anubee dump     -P com.example.app -F myapp.spec -o dump.jsonl       # reads the lib: line
```

Real examples: `specs/common-file.spec` and `specs/common-network.spec` mix `funcs:` lines
with `syscall:` lines. `ANUBEE-Detector/sim/rasp-checks.spec` mixes all three kinds to drive a whole
`anubee trace` run from one file.

## Flag reference

`-e`/`--spec` (inline) and `-F`/`--spec-file` (file) are the same on every engine. `dump` and
`mod` don't take `-e`/`--spec`. They only ever read specs from a file:

| Engine | Inline (`-e`/`--spec`) | File (`-F`/`--spec-file`) | Reads kinds |
|---|---|---|---|
| `funcs` | yes | yes | `funcs:` |
| `correlate` | yes | yes | `funcs:` |
| `syscalls` | yes | yes | `syscall:`, `lib:` |
| `dump` | no | yes | `lib:` |
| `mod` | no | yes | `mod:` |

`-l` (on `syscalls` and `dump`) is repeatable, and `lib:` lines are additive too: several
selectors are OR'd together, not last/first-wins. For `dump`, `lib:` lines supply PATTERN when
none is given positionally (all of them, not just the first). For `mod`, a `mod:` line
supplies the analyzer NAME the same way. For `syscalls`, `lib:` lines seed the library
selector list when no `-l` is given directly, and `syscall:`/`syscall:!` lines extend the
allow/deny list. Mixing `-s`/`-x` with a conflicting-direction spec line is a hard error.

## `syscalls`'s `-e` default kind

Unprefixed lines default to `funcs:` everywhere, with one exception: an unprefixed `-e` value
on `syscalls` defaults to `syscall:` instead, since that's the kind `syscalls` actually reads.
So `syscalls -e openat` means `syscall:openat`, and `syscalls -e '!ptrace'` means
`syscall:!ptrace`. This applies to `-e` only, never to `-F` files. A file loaded via `-F` keeps
the universal `funcs:` default on every engine, so shared multi-kind spec files (e.g.
`specs/common-network.spec`) keep working unchanged.

The default is skipped, and the value still parses as `funcs:`, if it already looks like a
`funcs:` target (contains `!` past a leading deny `!`, or `@`). A `funcs:`-style value pasted
into `syscalls -e` by mistake is then silently ignored by `syscalls`, as it always was, instead
of being mangled into a bogus syscall name.

`syscalls` prints a warning, both before the capture starts and again at the end of the run,
naming every `-e` value that used the default:
```
syscalls: warning — 2 -e spec(s) had no explicit kind prefix; assumed syscall: (this engine's -e default): openat connect
```

## Gotchas

- **Func-side glob silently fails to resolve.** Use `/regex/` for bulk selection on `funcs:`
  lines; glob only works on the module side.
- **`lib:` has no `/regex/` support**, unlike `funcs:`'s module side. Substring or glob only.
- **`syscalls --help` doesn't show `-e`/`-F` in its usage examples yet.** The options work;
  they're just missing from the doc string. Use this page as the reference until that's fixed.
