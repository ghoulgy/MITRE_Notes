# T1560.002 - Archive Collected Data: Archive via Library

Just some archive compression library comes across my mind 🤔

## zip

- zip64.dll (Win)
- zip64.so (Unix)
- zip32.dll (Win)
- zip32.so (Unix)
- libzip.dll (Win)
- libzip.so (Unix)

xzip [github](https://github.com/yuanjia1011/XZip-XUnZip)  
libzip [github](https://github.com/nih-at/libzip)

## gzip

- *glib.so (Unix)

## Winrar

- rarfile (python)

## zlib

- zlib (python)
- zlib32.dll (Win)
- zlib32.so (Unix)
- zlib64.dll (Win)
- zlib64.so (Unix)

zlib Wrapper [zpp](https://zpp-library.sourceforge.net/)

## aPLib

- aplib.dll

Download [link](https://ibsensoftware.com/download.html)

## Hunt

For .dll library, file name might be change  
Identify unsual windows binaries that loads these dlls  
Identify any bulk File Events on those file extension mentioned in [T1560.001](https://github.com/ghoulgy/MITRE_Notes/blob/master/T1560.001/T1560_001_Archive_Collected_Data_Archive_via_Utility.md#possible-extention-to-be-compress-and-exfiltrate-not-limited-to-these)