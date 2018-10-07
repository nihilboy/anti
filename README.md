# ANTI 
### Automated Integration of Anti-Reversing methods in PE executables  
###### _only x86 support_
## Currently using the following techniques:

**Unhooking**
 - Disables user-mode function hooks by manually loading ntdll.dll from disk and check for modifications. 
 - If modifications exist it overwrites with the valid ntdll and calls anti-debug functions based on ntdll from there.
 - _Todo:Unhooking for every loaded dll_ 

**Anti-debugging**
 - IsDebuggerPresent()
 - PEB.BeingDebugged flag using speculative execution
 - PEB.NtGlobalFlag
 - Heap Flags
 - Self-Debugging
 - Anti-Step-Over
 - NtSetInformationThread()
 - Dynamic TlsCallbacks
 - NtQueryInformationProcess()
 - RDTSC
 - RtlQueryProcessDebugInformation()
 - Selectors
 - Uses NtTerminateProcess() or SwitchDesktop() or NtShutdownSystem() to terminate/crash the debugging/VM session 

**Anti-VM**
 - CPUID (Hypervisor presence)<br />
 - CPUID (Hypervisor vendor)<br />
 - Number of Processors<br />
 - Device Drivers<br />
 - NtGetTickCount

**Process Injection**
 - ANTI automatically migrates in a remote process when it detects a debugger using NtCreateThreadEx technique.

## ANTI bypasses the following debuggers and antidebug solutions:

 - Idapro, Version 7, 5
 - Immunity Debugger, Version 1.85
 - OllyDebugger v1.10, v.2
 - CheatEngine
 - x64dbg, Build Aprl 5 2018
 - Windbg 10
 - Obsidian debugger, Version 0.11
 - Microsoft Visual Studio Debugger, Version 15.4.0
 - PhantOm v1.85
 - StrongOD v0.4.8.892
 - OllyAdvanced v1.27
 - SharpOD v0.6
 - aadp v0.2
 - HideDebugger v1.2.4
 - IDA Stealth
 - OllyExt
 - makin
 - ScyllaHide 
 - Apate
 - ApiMonitor v2

## Usage:

 - anti.exe &lt;target file> &lt;section name> &lt;pid>

## POC: Bypassing ScyllaHide on x32dbg 

![alt text](https://github.com/nihilboy/anti/blob/master/scylla.jpg "Logo Title Text 1")
![alt text](https://github.com/nihilboy/anti/blob/master/scylla_crash.jpg "Logo Title Text 1")

## License ##
ANTI is licensed under the MIT License.


_Credits to Peter Ferrie for his [“Ultimate”Anti-Debugging Reference](http://pferrie.host22.com/papers/antidebug.pdf)_
