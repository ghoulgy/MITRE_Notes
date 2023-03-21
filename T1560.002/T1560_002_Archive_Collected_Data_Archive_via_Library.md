# T1560.002 - Archive Collected Data: Archive via Library

Just some archive compression library comes across my mind 🤔  

## zip

- zipfile (python)
- zip64.dll (Win)
- zip64.so (Unix)
- zip32.dll (Win)
- zip32.so (Unix)
- libzip.dll (Win)
- libzip.so (Unix)

xzip [github](https://github.com/yuanjia1011/XZip-XUnZip)  
libzip [github](https://github.com/nih-at/libzip)

## gzip

- gzip (python)
- *glib.so (Unix)

## Winrar

- rarfile (python)

## bzip2

- bzip2 (python)

## zlib

- zlib (python)
- zlib32.dll (Win)
- zlib32.so (Unix)
- zlib64.dll (Win)
- zlib64.so (Unix)

zlib Wrapper [zpp](https://zpp-library.sourceforge.net/)

## tar

- tarfile (python)

How to use [tarfile](https://www.python-engineer.com/posts/tarfile-python/) in python

## aPLib

- aplib.dll

Download [link](https://ibsensoftware.com/download.html)

## C++ boost library

It supports variable type of compression (e.g. gzip, zlib)  

gzip [example](https://techoverflow.net/2020/01/13/how-to-gzip-compress-on-the-fly-in-c-using-boostiostreams/)

## Hunt

- For .dll library, file name might be change  
- Identify unsual windows binaries that loads these dlls  
- Identify any bulk File Events on those file extension mentioned in [T1560.001](https://github.com/ghoulgy/MITRE_Notes/blob/master/T1560.001/T1560_001_Archive_Collected_Data_Archive_via_Utility.md#possible-extention-to-be-compress-and-exfiltrate-not-limited-to-these) or sensitive keyword based on your company business  
- There are various type of libraries that can be loaded corresponding to the programming language used (e.g. Python, C++) and the OS env used (e.g. Windows, Unix), at least for custom malware  
- File size might be a good indicator as well if there are large amount of file being read by the process and user under certain period of time
