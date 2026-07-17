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

**Recommended:** that's [ARES-Desktop](https://github.com/michaelaurelio/ARES-Desktop) in the demo above, taking the raw output nobody wants to read by hand and turning it into something you can actually follow. It drives `anubee` for you while it's at it. [Click here](https://github.com/michaelaurelio/ARES-Desktop) and follow its own README for setup.

**Full capability:** need more than what Desktop gives you? The binary puts every subcommand and flag directly in your hands. Full walkthrough, prerequisites included: [`docs/getting-started.md`](docs/getting-started.md).

---

## Watch It Get Caught, Live

You've seen what Anubee can do and how to run it. Here's proof that the quiet part of that promise is real, not just something we say.

[ARES-Detector](https://github.com/michaelaurelio/ARES-Detector) is a companion app whose only job is catching tools like Anubee in the act. It runs real anti-tamper checks and turns its screen red the instant it notices anything watching it.

<table>
<tr>
<td align="center" width="33%"><img src="assets/detector-clean.png" width="220"><br><sub>Fresh install. Green "SECURE" banner, 0/4 tripped, every check passing.</sub></td>
<td align="center" width="33%"><img src="assets/detector-autoloop.png" width="220"><br><sub>Auto-loop switched on, so it keeps re-checking itself. Still green, still 0/4.</sub></td>
<td align="center" width="33%"><img src="assets/detector-compromised.png" width="220"><br><sub>Seconds after <code>anubee mod prop-read</code> attaches: the banner flips to red "COMPROMISED".</sub></td>
</tr>
</table>

That flip happened on the very next automatic check, not staged and not delayed, and the log behind it names the exact memory address it caught. `prop-read` is one of the few Anubee capabilities detectable by design. Point one of the undetectable ones at the same app instead, `syscalls`, `lib`, or `dump`, and the banner never moves.

---

**Curious how any of this actually works under the hood?** 

Full architecture, engine internals, the trace schema, detectability analysis, and every known limitation live in [DOCUMENTATION.md](DOCUMENTATION.md).

---

## License

See [LICENSE](LICENSE).

---

## Authors

- [michaelaurelio](https://github.com/michaelaurelio)
- [chronopad](https://github.com/chronopad)
- [Ringoshiroku](https://github.com/Ringoshiroku)
