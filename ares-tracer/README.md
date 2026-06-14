# ARES: Stealthier Native-Level Function Call Tracer for Android Application Dynamic Analysis Using eBPF

Dynamic analysis tools leave observable artifacts in the target process. For example, Frida requires injecting a shared library agent, which can be detected via blablabla.

ARES is a dynamic analysis tool for tracing native-level function calls. It leverages eBPF to attach probes on target functions, without ptrace or injecting an agent to the target’s memory, leaving minimal footprint and being stealthier. This helps for quickly tracing arguments and return values of native functions called by the application without needing to reverse engineer and patch checks done by the application first. This can also help in identifying the libraries performing those checks and find the location of the checks itself, assisting in the reverse engineering process.

## Features

- Dynamically loaded library tracing
	- No userland footprint (unless attach uprobe)
	- Export library from memory
	- ==Rec: Add unique library listing ==
- Native function call argument and return value tracing
	- BRK at function prelude footprint (integrity check, prelude check)
	- Specify number and type for argument and return value (V, S, F)
	- Group function specifications into multiple files for categorization
	- Call stack visibility to assist reverse engineering
- Flexible tracing via application spawn or attach to PID
	- No userland footprint (unless attach uprobe)
- Process fork and exit tracing
	- No userland footprint
	- Implemented as module
- Property access tracing
	- BRK at function prelude footprint (integrity check, prelude check)
	- Implemented as module
	- ==Rec: Add unique module listing + call count report==
- Execve tracing
	- No userland footprint
	- Implemented as module
- Additional
	- Export output to CSV and JSONL

## Limitations

Native function call tracing attaches uprobe and uretprobe, which puts a BRK instruction at the function prelude. This is detectable by memory integrity or function prelude check.

## Prerequisites

- Docker
- adb (root access)

## Build and Deploy

```
git clone https://github.com/chronopad/ares-tracer/.git --recurse
cd ares-tracer
./scripts/build.sh                # Build ARES with docker
./scripts/deploy.sh               # Deploy ARES to /data/local/tmp
```

## Usage

```
cd /data/local/tmp
./ares-tracer -P com.example.app -L
./ares-tracer -P com.example.app -F specs/common-string.spec
./ares-tracer -P com.example.app -m proc-event
./ares-tracer -P com.example.app -m prop-read -F specs/common-getprop.spec
```
