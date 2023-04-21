# How startup registry entry been executed?

Found out these 3 processes are responsible for that:

- explorer.exe
- runonce.exe
- winlogon.exe

Based on the analysis, these registry value data items will be executed via:

- COM object (`IShellFolder` and `IContextMenu`)
- CreateProcessAsUser
- rundll32 shell32.dll, ShellExec_RunDLL <FILE_NAME>

## Analysis For explorer.exe and runonce.exe

Performed quick static analysis for this one

Inside `ProcessRun6432()` function in `explorer.exe`, `runonce.exe` will be executed inside `SHCreateProcessWithArgs()`

![call_runonce_from_explorer.png](./Image_T1547.001/call_runonce_from_explorer.png)

![explorer_run6432_param.PNG](./Image_T1547.001/explorer_run6432_param.PNG)

Inside `runonce.exe`, the `ParseCmdLine()` will parse the paramenter that passed from `explorer.exe` and decide what to do next (In this case `/Run6432` is passed as parameter)  

![runonce_parse_cmd.PNG](./Image_T1547.001/runonce_parse_cmd.PNG)

`SHEnumRegApps` will read all the value data in `\Run` via `RegEnumValueW` and executes them one by one via `Startup_ExecuteRegAppEnumProc()`

![runonce_exec_reg_app_enum_proc.png](./Image_T1547.001/runonce_exec_reg_app_enum_proc.png)

![runonce_SHEnumRegApps.PNG](./Image_T1547.001/runonce_SHEnumRegApps.PNG)

`runonce.exe` will execute the binary stored in registry `\Run` via `rundll32.exe shell32.dll, ShellExec_RunDLL ?0x%X?%s` via `ExecuteRegAppEnumProc()` -> `Startup_ExecuteRegAppEnumProc()` -> `_ShellExecuteRegAppWithJobObject()`

`%s` contains the full path of the binary stored in registry `\Run`

![rundll32_shell32_dll_reg_run_data.PNG](./Image_T1547.001/rundll32_shell32_dll_reg_run_data.PNG)

There is another alternative by using COM object `IShellFolder` and `IContextMenu` which will talk about in next section

## Analysis on "runonce.exe /AlternateShellStartup"

![rundll32_shell32_dll_reg_run_data.PNG](./Image_T1547.001/runonce_alternateshellstartup.PNG)

**(1)**
`ProcessRunOnce()` from HKLM registry can be execute if
`HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\RunStuffHasBeenRun` removed

It will rerun the same executable with parameter `/RunOnce6432`

> Remember since it is HKLM, elevated permission required.  

There is **IsOS(0x1Eu)** check before moving into ``SHEnumRegApps()`.

> OS_WOW6432 (30, 0x1E) means the program is a 32-bit program running on 64-bit Windows

![rundll32_shell32_dll_reg_run_data.PNG](./Image_T1547.001/runonce_RunStuffHasBeenRun.PNG)

**(2)** The execution of `ProcessRun()` can be done with some modification on jump condition for GetSystemMetrics(0x43).

> SM_CMOUSEBUTTONS (0x43)  
The number of buttons on a mouse, or zero if no mouse is installed

This means It will only run before user login into their own session.  

After the flow modification, it will read the `\Run` data and execute via COM object.

In `ProcessRun()` function, It will load a hardcoded [struct STARTUP_ITEM](./struct_STARTUPGROUP_ITEM.txt)

The struct contains 2 registry key data as mentioned below:

- Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run (HKCU/HKLM)
- Software\Microsoft\Windows\CurrentVersion\Run (HKCU/HKLM)

![runonce_processrun.PNG](./Image_T1547.001/runonce_processrun.PNG)

`_RunStartupGroup()` will load `SHEnumRegApps()` which will enumerate and load all the registry key value data in key in `strcut STARTUP_ITEM`. Then, these data will be load in  `Startup_ExecuteRegAppEnumProc()`.

![runonce_runstartupgroup.PNG](./Image_T1547.001/runonce_runstartupgroup.PNG)

Inside `Startup_ExecuteRegAppEnumProc()`, it will load `ExecuteRegAppEnumProc()` -> `_ShellExecuteRegAppWorker()` -> `ShellExecuteRunApp()`.

![runonce_shellexecuterunapp.PNG](./Image_T1547.001/runonce_shellexecuterunapp.PNG)

The `shell32.dll!CDefFolderMenu::InvokeCommand()` will execute the registry value data fetch from the registry key in `struct STARTUP_ITEM`.

`InvokeCommand()` will accept only one paramter with `struct _CMINVOKECOMMANDINFOEX` format.

Here is the variable assignment for the structure used in `ShellExecuteRunApp()`.

```c++
    v28.lpDirectoryW = a3;
    v28.cbSize = 0x68;
    v28.hwnd = 0i64;
    v28.fMask = 0x4500;
    v28.nShow = a4;
    v28.lpParametersW = a2;
```

Note: rax -> `shell32.dll!CDefFolderMenu::InvokeCommand()`.

![runonce_dispatch_call.png](./Image_T1547.001/runonce_dispatch_call.png)

Just wrote a PoC on file execution using `InvokeCommand` [here](https://github.com/ghoulgy/RandomCodes/blob/master/cpp/icontextmenu_invokecommand.cpp).

**(3)** After the execution of `ProcessRun()`, `ProcessPerUserRunOnce()`, only the value data from following registry will be loaded:

- Software\Microsoft\Windows\CurrentVersion\RunOnce (HKCU only)

Based on the flow of the code, you can simply add any files into `HKCU\...\RunOnce` and execute `runonce.exe /AlternateShellStartup`, it will execute any files inside the registry key and remove its key value afterwards.

## Analysis on UserInit or Shell in \Software\Microsoft\Windows NT\CurrentVersion\Winlogon

Registry value data in `UserInit` executed in `WLGeneric_ShellStartup_Execute`. Meanwhile, registry value data in `Shell` executed in `WLGeneric_ShellRestart_Enter`. 

Why we have to add comma `,` in order to make this work?

Based on the code below, it can be seen that there is a split done by `wcstok()` with comma `,` as delimiter. The output of `wcstok()` will be enumerate in `for` loop. Inside the loop, there is a space check by `iswspace()` to ensure the first character is a non-space character. If the first character is a non-space character, it will pass into `CUser::CreateProcessW()` -> `CreateProcessAsUserW` as `lpCommandLine`.

```text
(Input) explorer.exe, c:\Users\<USER_NAME>\random.bat -> wcstok() ->
(Output in 3rd param) explorer.exe\x00\x20c:\Users\<USER_NAME>\random.bat\0

(Input) "explorer.exe" -> iswspace() -> (Output) "explorer.exe"
(Input)" c:\Users\<USER_NAME>\random.bat" -> iswspace() (Output) "c:\Users\<USER_NAME>\random.bat"
```

![winlogon_split_comma.png](./Image_T1547.001/winlogon_split_comma.png)

## Analysis on Startup Folder Path

This path is only for `.lnk` file.

`Explorer.exe` will create a thread `RunStartupAppsThreadProc()` which initiate the process to execute file in startup path.
![startup_path_CreatThread.PNG](./Image_T1547.001/startup_path_CreatThread.PNG)

From `RunStartupAppsThreadProc()` ---Executes---> `_ProcessStartupGroup()`
![startup_path_RunStartupAppsThreadProc.PNG](./Image_T1547.001/startup_path_RunStartupAppsThreadProc.PNG)

From `_ProcessStartupGroup()` ---Executes---> `EnumFolder()`  

In here, found out there is a `struct_startup_folder` that contains some interesting stuffs `CSIDL_COMMON_STARTUP` and strings `StartupFolder`

```c++
struct struct_startup_folder{
    _QWORD CSIDL; // 0x18, CSIDL_COMMON_STARTUP
    _QWORD unknown2;
    _QWORD string_path; // StartupFolder
}
```

![startup_path_ProcessStartupGroup.PNG](./Image_T1547.001/startup_path_ProcessStartupGroup.PNG)

From `EnumFolder()` ---Executes---> `ExecStartupEnumProc`
![startup_path_EnumFolder.PNG](./Image_T1547.001/startup_path_EnumFolder.PNG)

COM Object `ISHellLinkW` and `IContextMenu` loaded and execute the .lnk file in the startup path via `InvokeCommand`

![startup_path_ExecStartupEnumProc.PNG](./Image_T1547.001/startup_path_ExecStartupEnumProc.PNG)

It can be verify via stack trace from `procmon`  
The stack offset will redirect to the relevant line of code.

![startup_path_procmon_InvokeCommand.png](./Image_T1547.001/startup_path_procmon_InvokeCommand.png)

## References

<https://medium.com/@boutnaru/the-windows-process-journey-userinit-exe-userinit-logon-application-650062f61df3>  
<https://www.nutanix.com/sg/blog/windows-os-optimization-essentials-part-4-startup-items>  
<https://github.com/Open-Shell/Open-Shell-Menu/blob/master/Src/ClassicExplorer/ExplorerBand.cpp>  
<https://www.hexacorn.com/blog/2019/02/23/beyond-good-ol-run-key-part-104/>  
<https://www.geeksforgeeks.org/wcstok-function-in-c-with-example/>  
<https://www.nirsoft.net/articles/find_special_folder_location.html>
