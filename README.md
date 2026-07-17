# Anubee: All-Seeing Eye for Android Apps

<p align="center" width="100">

<img src="assets/banner.png" alt="Anubee banner" width="800">

</p>

---

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv2-blue.svg"></a>
  <a href="#"><img src="https://img.shields.io/badge/Platform-arm64%20%7C%20aarch64-lightgrey"></a>
  <a href="#"><img src="https://img.shields.io/badge/Built%20With-eBPF-orange"></a>
  <a href="#"><img src="https://img.shields.io/badge/Focus-Android%20RASP%20%2F%20Malware%20Analysis-red"></a>
</p>

---

Ever wanted to know **exactly** what an app is really doing?

**You're in the right place!**

Anubee sees what an app is doing, no matter how hidden it is. Most of the time, it watches silently, without leaving a trace.

---

## Demo

Coming soon. While that's in the works, here's the full list of what Anubee can actually do:

---

## Capabilities

Here's exactly what each subcommand is for:

| Subcommand | What it's for |
|---|---|
| `anubee syscalls` | Stealthy behavioral triage: see what an app does without it ever knowing you're watching |
| `anubee funcs` | Deep function-level reverse engineering: exact arguments, return values, and timing, used when staying hidden isn't the priority |
| `anubee correlate` | Tying a specific function to the syscalls it triggers, to understand exactly what a suspicious function does |
| `anubee lib` | Discovering every native library an app loads, including ones it only loads dynamically, mid-run |
| `anubee dump` | Pulling a decrypted or packed native library out of a running app and rebuilding it into something you can open in a disassembler |
| `anubee trace` | Running `syscalls` and `funcs`/`lib` together from one launch, when you want both views at once |
| `anubee mod` | Ready-made detection for specific malicious behavior (mass-deletion, exfiltration, accessibility abuse) without writing your own probe spec |

---

## Quick start

**The fastest way in is [ARES-Desktop](https://github.com/michaelaurelio/ARES-Desktop).** A trace is worthless if you can't read it back: once you have one, you're staring down millions of syscalls and raw addresses, cross-referencing every meaningful hit in a disassembler by hand. ARES-Desktop closes that loop: load the trace, and follow the whole chain, from Java method call, to native function, to the exact address you'd open in a disassembler. It can drive `anubee` directly against a connected device too, so it stays the one place you actually work from. See its own README for setup.

Prefer the raw binary instead? Anubee needs a rooted arm64/aarch64 Android device with an eBPF + BTF kernel. Native build and first-trace walkthrough: [`docs/getting-started.md`](docs/getting-started.md).

```sh
# Grab the prebuilt binary from Releases, or build it (container, no host setup):
git clone --recurse-submodules <repo-url> anubee
cd anubee
./scripts/build.sh            # -> build/anubee

./scripts/deploy.sh           # adb push build/anubee + specs to /data/local/tmp

# First trace: every syscall com.example.app's librasp.so makes
adb shell "su -c '/data/local/tmp/anubee syscalls -P com.example.app -l librasp.so \
                   -o /data/local/tmp/trace.jsonl'"
```

The [Releases](../../releases) page has the prebuilt static binary. Most
users never need to build.

---

## Don't Take Our Word for It

"Detectability firewall" is a nice claim, but a claim isn't proof. [ARES-Detector](https://github.com/michaelaurelio/ARES-Detector) is a genuine reference RASP: real anti-tamper checks, a UI that turns red the instant any tool writes into its memory, including Anubee's own loud engines. Point a quiet capability at it and watch the screen stay clean. That absence is the proof.

---

**Curious how any of this actually works under the hood?** Full architecture, engine internals, the trace schema, detectability analysis, and every known limitation live in [DOCUMENTATION.md](DOCUMENTATION.md).

---

## License

See [LICENSE](LICENSE).

---

## Authors

- [michaelaurelio](https://github.com/michaelaurelio)
- [chronopad](https://github.com/chronopad)
- [Ringoshiroku](https://github.com/Ringoshiroku)
