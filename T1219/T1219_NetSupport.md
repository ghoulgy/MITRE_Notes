# T1219: Remote Access Software NetSupport

## Description

It is a remote access tool that allows attacker to take control on the system remotely. It requires the listener runs on the background.

So far the listener only listen on port `5405` or `5421`

These two libraries, `PCICL32.dll` and `TCCTL32.dll` did most of the job on the RAT feature.

![net_support_netstat.PNG](./Image_T1219/net_support_netstat.PNG)

Here is the IDAPro decompiler view on `TCCTL32.dll`

![net_support_port.PNG](./Image_T1219/net_support_port.PNG)

> There is a [SANS site](https://isc.sans.edu/services.html) which list down any port with its corresponding service.

The connecting server will be specified in `GateawayAddress`

![netsupport_client_ini.PNG](./Image_T1219/netsupport_client_ini.PNG)

## Hunt

### Network

Hunt for any suspicious port that listening to either `5405` or `5421` since this is hardcoded within the NetSupport tools. (Not sure if there is a setting on the listener builder that can modify the port number used)

## Reference

<https://isc.sans.edu/services.html>
