# T1546.015 - Event Triggered Execution: Component Object Model Hijacking

## Keynotes

Require admin privilege  
LocalServer/LocalServer32 - File type exe
InprocServer/InprocServer32 - File type dll  
treatas - Delegation of clsid/progid

## Execution

### Setting Up Registry

HKCU & InprocServer32

- HKCU\SOFTWARE\Classes\CLSID\\{\<CLSID\>}
  - Value: <ANY_NAME>

- HKCU\SOFTWARE\Classes\CLSID\\{\<CLSID\>}\InprocServer32
  - Value: <FULL_FILE_PATH>

- HKCU\SOFTWARE\Classes\CLSID\\{\<CLSID\>}\InprocServer32
  - Name: ThreadingModel
  - Value: Apartment/Both

treatas

- HKCU\SOFTWARE\Classes\\<ANY_NAME>
  - Value: <ANY_NAME>

- HKCU\SOFTWARE\Classes\\<ANY_NAME>\CLSID"
  - Value: {<CLSID_ORI>}

- HKCU\SOFTWARE\Classes\CLSID\\{\<CLSID_ORI\>}
  - Value: <ANY_NAME>

- HKCU\SOFTWARE\Classes\CLSID\\{<CLSID_ORI>}\InprocServer32
  - Value: <FULL_FILE_PATH>

- HKCU\SOFTWARE\Classes\CLSID\\{<CLSID_ORI>}\InprocServer32
  - Name: ThreadingModel
  - Value: Apartment/Both

- HKCU\SOFTWARE\Classes\CLSID\\{<CLSID_DELEGATE>}  

- HKCU\SOFTWARE\Classes\CLSID\\{<CLSID_DELEGATE>}\TreatAs
  - Value: {<CLSID_ORI>}

### LOLBIN

- rundll32 -sta <clsid/progid>
- rundll32 -localserver \<clsid>
- New-object -comobject \<OBJNAME\>
- \[activator\]::CreateInstance([type]::GetTypeFromCLSID("<YOUR_CLSID>"))

### Legit binary Execution (Not limited to)

- Firefox
- IExplorer

## Analysis

Can be find in my [Blog Post](https://medium.com/@ghoulsec/reddev-5-rundll32-com-hijack-executor-in-c-40b632fc7e37) 😁 (rundll32.exe only)

## Hunt

Ideas to look for Legit Software Executable COM Hijack (Manual & Tedious way):

```text
Procmon -> Run any Program -> Filter (Operation = RegOpenKey, Path contains CLSID/inprocserver/localserver/treatas, Result = No Name Found) 
```

Tools: https://github.com/nccgroup/acCOMplice

## Detection

### Registry based

Look for any binary inside regkey `LocalServer*/InprocServer*`

### Process

Any process event of adding/modify registry of LocalServer*/InprocServer*/treatas

### LOLBIN Execution

Look for switches keyword in rundll32/powershell/etc.

## References

<https://www.221bluestreet.com/offensive-security/windows-components-object-model/com-hijacking-t1546.015#scriptleturl-fileless-com-execution>  
<https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/>  
<https://pentestlab.blog/2020/05/20/persistence-com-hijacking/>  
<https://github.com/ghoulgy/RandomCodes/blob/master/cpp/com_hijack_progid_clsid.cpp>
