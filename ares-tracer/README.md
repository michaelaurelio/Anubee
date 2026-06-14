# ARES: Stealthier Native-Level Function Call Tracer for Android Application Dynamic Analysis using eBPF

Dynamic analysis tools leave observable artifacts in the target process. For example, Frida requires injecting a shared library agent, which can be detected via blablabla.

ARES is a dynamic analysis tool for tracing native-level function calls. It leverages eBPF to attach probes on target functions, without ptrace or injecting an agent to the target’s memory, leaving minimal footprint and being stealthier. This helps for quickly tracing arguments and return values of native functions called by the application without needing to reverse engineer and patch checks done by the application first. This can also help in identifying the libraries performing those checks and find the location of the checks itself, assisting in the reverse engineering process.

### Features

- Dynamically loaded library tracing
	- No userland footprint (unless attach uprobe)
	- Export library from memory
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
	- Rec: Add unique module listing + call count report
- Execve tracing
	- No userland footprint
	- Implemented as module
- Additional
	- Export output to CSV and JSONL