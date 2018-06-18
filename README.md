# antidebug_protector
 
## Currently using the following techniques:<br />
### -IsDebuggerPresent()<br />
### -PEB.BeingDebugged flag using speculative execution<br />
### -PEB.NtGlobalFlag<br />
### -Heap Flags<br />
### -Self-Debugging<br />
### -Anti-Step-Over<br />
### -interrupt 0x2d<br />
### -NtSetInformationThread()<br />
### -Dynamic TlsCallbacks<br />
### -NtQueryInformationProcess<br />
### -RDTSTC<br />
### -RtlQueryProcessDebugInformation()<br />
### -RtlQueryProcessHeapInformation()<br />
### -Selectors<br />
### -BlockInput<br />
### -uses SwitchDesktop() to crash the debugging session<br />

_Credits to Peter Ferrie for his [“Ultimate”Anti-Debugging Reference](http://pferrie.host22.com/papers/antidebug.pdf)_
