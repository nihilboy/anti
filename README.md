# Automated Integration of Anti-Reversing methods in PE executables  
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
##### - NtSetInformationThread()<br />
##### - Dynamic TlsCallbacks<br />
##### - NtQueryInformationProcess()<br />
##### - RDTSC<br />
##### - RtlQueryProcessDebugInformation()<br />
##### - RtlQueryProcessHeapInformation()<br />
##### - Selectors<br />
##### - uses SwitchDesktop() to crash the debugging session<br /><ul/>

### Anti-VM<br />
___
##### - CPUID (Hypervisor presence)<br />
##### - CPUID (Hypervisor vendor)<br />
##### - Number of Processors<br />
##### - Device Drivers<br />
##### - NtGetTickCount

### Process Injection
___
##### ANTI automatically migrates in a remote process when it detects a debugger using NtCreateThreadEx technique.

## ANTI bypasses the following debuggers and antidebug solutions:
___
##### - Idapro, Version 7, 5
##### - Immunity Debugger, Version 1.85
##### - OllyDebugger v1.10, v.2
##### - CheatEngine
##### - x64dbg, Build Aprl 5 2018
##### - Windbg 10
##### - Obsidian debugger, Version 0.11
##### - Microsoft Visual Studio Debugger, Version 15.4.0
##### - PhantOm v1.85
##### - StrongOD v0.4.8.892
##### - OllyAdvanced v1.27
##### - SharpOD v0.6
##### - aadp v0.2
##### - HideDebugger v1.2.4
##### - IDA Stealth
##### - OllyExt
##### - makin
##### - ScyllaHide 
##### - Apate
##### - ApiMonitor v2

### POC: trying to debug putty.exe on x64dbg with ScyllaHide
![alt text](https://github.com/nihilboy/anti/blob/master/scylla.jpg "Logo Title Text 1")
![alt text](https://github.com/nihilboy/anti/blob/master/scylla_crash.jpg "Logo Title Text 1")

### Usage:
anti.exe &lttarget file> <section name> <pid>_


_Credits to Peter Ferrie for his [“Ultimate”Anti-Debugging Reference](http://pferrie.host22.com/papers/antidebug.pdf)_
