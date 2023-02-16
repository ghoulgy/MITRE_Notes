# T1560.001 - Archive Collected Data: Archive via Utility  

## Possible Attack Vector  

- Insider (Employee of company)
- External (Threat Actor from outside the network)

## Binary

### Winzip

```cmd
C:\Program Files\WinZip\wzzip  <zip_destination>  <list of files>
```

winzip [Ref](https://www.windows-commandline.com/winzip-command-line/)

### winrar/rar.exe

```cmd
rar a -hp<redacted> -ri10 -r -y -u -m2 -v30m "%temp%\~res.dat" "d:\<redacted>\*.*" "d:\$RECYCLE.BIN\*.doc*" "d:\$RECYCLE.BIN\*.pdf*" "d:\$RECYCLE.BIN\*.xls*" "d:\Recycled\*.doc*" "d:\Recycled\*.pdf*" "d:\<redacted>\*.pdf"
```

### tar

- Switch for compress -> `c`
  - czvf
  - cvf
  - cf
  - c

tar [Ref](https://www.dynamsoft.com/codepool/create-extract-update-tar-gzip-windows.html)

### 7zip (7z\*) / gzip

- Switch for compress -> `a`

```cmd
C:\Windows\system32\cmd.exe/c c:\users\public\7zr.exe a -bso0 -bse2 -bsp2 -p<password_from_comamnd_line> c:\users\public\path.7z c:\users\public\20190423\
```

gzip [Ref](https://www.dynamsoft.com/codepool/create-extract-update-tar-gzip-windows.html)

### Peazip

Direct batch archiving functions as`-add*`  

```txt
-add2pea, -add2crypt, -add27z, -add27zmail, -add2separate7z, -add2sfx7z, -add2sfx7zmail, -add2zip, -add2zipmail, -add2separatezip 
```

```cmd
peazip -add2zip <source file list>
```

peazip [Ref](https://peazip.github.io/peazip-command-line.html)

### makecab

```txt
makecab <source> <destination>
```

makecab [Ref](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/makecab)

### Zlib

```cmd
zlib.exe <source> <destination>
```

zlib [Ref](https://github.com/kevin-cantwell/zlib)  
zlib-flate (doesn't work in my machine) [Ref](https://www.mankier.com/1/zlib-flate)

### pigz

```shell
pigz <source>
```

pigz [Ref](https://github.com/madler/pigz)

## Powershell Command

- Archive-Compact  
  - `Archive-Compact <src> <dest>`  
  - `Archive-Compact -Path <src> <dest>`  
  - `Archive-Compact -Path <src> -DestinationPath <dest>`  
- 7Zip (https://github.com/thoemmi/7Zip4Powershell)  
- GZipStream

## Possible Extention To be Compress and Exfiltrate (Not limited to these)

```txt
.exe .msi .dll 
.db .mdb .sql .dbf
.htm .html .css .jar .js 
.conf .xml .tmp
.log .dmp .bak .dat  
.avi .mp3 .mp4 .mpg .mpeg 
.asp .aspx .inc .jpg .java .cpp .py .cs .rs
.xl* .ppt* .doc* .csv .pdf .one .mpp .pst .eml
```

## Archive extension list (Not limited to these)  

```txt
.zip .7z .tar .tgz .rar .gz .arj
```