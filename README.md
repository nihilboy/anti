# Automated Integration of anti-Reversing methods in PE executables  
## Currently using the following techniques:<br />
### Unhooking
##### - Disables user-mode function hooks by manually loading ntdll.dll from disk and check for modifications. 
##### - If modifications exist it overwrites with the valid ntdll and calls anti-debug functions based on ntdll from there.
##### -_Todo: Unhooking for every loaded dll_ 

### Anti-debugging<br />
___
##### - IsDebuggerPresent()<br/>
##### - PEB.BeingDebugged flag using speculative execution<br />
##### - PEB.NtGlobalFlag<br />
##### - Heap Flags<br />
##### - Self-Debugging<br />
##### - Anti-Step-Over<br />
##### - interrupt 0x2d<br />
##### - NtSetInformationThread()<br />
##### - Dynamic TlsCallbacks<br />
##### - NtQueryInformationProcess()<br />
##### - RDTSC<br />
##### - RtlQueryProcessDebugInformation()<br />
##### - RtlQueryProcessHeapInformation()<br />
##### - Selectors<br />
##### - BlockInput()<br />
##### - uses SwitchDesktop() to crash the debugging session<br /><ul/>
### Anti-VM<br />
___
##### - CPUID (Hypervisor presence)<br />
##### - CPUID (Hypervisor vendor)<br />
##### - Number of Processors<br />
##### - Device Drivers<br />

## ANTI bypasses the following debuggers and antidebug solutions:
##### - Idapro
##### - Immunity Debugger
##### - OllyDebugger 
##### - CheatEngine
##### - x64dbg
##### - Windbg
##### - PhantOm (anti-debug plugin for Olly) 
##### - StrongOD (anti-debug plugin for Olly)
##### - OllyAdvanced (anti-debug plugin for Olly) 
##### - makin
##### - ScyllaHide (anti-debug plugin for Olly/Ida/x64dbg)

### POC: trying to debug putty.exe on x64dbg with ScyllaHide
![alt text](https://github.com/nihilboy/anti/blob/master/scylla.jpg "Logo Title Text 1")
![alt text](https://github.com/nihilboy/anti/blob/master/scylla_crash.jpg "Logo Title Text 1")


_Credits to Peter Ferrie for his [“Ultimate”Anti-Debugging Reference](http://pferrie.host22.com/papers/antidebug.pdf)_
