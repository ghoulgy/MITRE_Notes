# T1059.001 - Command and Scripting Interpreter: PowerShell

## Powershell without Powershell.exe

Powershell Dll loader: [Powershdll](!https://github.com/p3nt4/PowerShdll)  

These are the process that will perform DLL load on the file

- rundll32.exe
- installutil.exe
- regsvcs.exe
- regasm.exe
- regsvr32.exe

### Based on the procmon test

During the initial load of Powershdll, we can see the `ImageLoad` event with `System.Management.Automation.ni.dll`  
After that, most of the time `System.Management.Automation.dll` will be read (`CreateFile` event) by the same calling process  
It will create thread (`Thread Create` event) for any command runs under itself  

## Process Chian for interactive mode

``` cmd
rundll32.exe (rundll32  PowerShdll.dll,main) -> conhost.exe (\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1)
```

> There is Powershdll for exe version which have similar pattern but it won't load any `System.Management.Automation` related dll after its initialization

## Ref

<https://github.com/p3nt4/PowerShdll>  
<https://www.paloaltonetworks.com/blog/security-operations/stopping-powershell-without-powershell>  
<https://www.ired.team/offensive-security/code-execution/powershell-without-powershell>  
