# On the fly malware hardening through anti-debugging & anti-VM techniques
 
## Currently using the following techniques:<br />
### Anti-debugging<br />
...
##### * IsDebuggerPresent()<br />
##### *PEB.BeingDebugged flag using speculative execution<br />
##### *PEB.NtGlobalFlag<br />
##### *Heap Flags<br />
##### *Self-Debugging<br />
##### *Anti-Step-Over<br />
##### *interrupt 0x2d<br />
##### *NtSetInformationThread()<br />
##### *Dynamic TlsCallbacks<br />
##### *NtQueryInformationProcess<br />
##### *RDTSC<br />
##### *RtlQueryProcessDebugInformation()<br />
##### *RtlQueryProcessHeapInformation()<br />
##### *Selectors<br />
##### *BlockInput<br />
##### *uses SwitchDesktop() to crash the debugging session<br />
### Anti-VM-<br />
...
##### *CPUID (Hypervisor presence)<br />
##### *CPUID (Hypervisor vendor)<br />
##### *Number of Processors<br />
##### *Device Drivers<br />


_Credits to Peter Ferrie for his [“Ultimate”Anti-Debugging Reference](http://pferrie.host22.com/papers/antidebug.pdf)_
