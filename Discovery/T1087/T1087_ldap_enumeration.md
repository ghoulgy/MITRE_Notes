# T1087 - LDAP Enumeration

LDAP search is widely used by various tools to perform reconnaissance, e.g. ADExplorer, SharpHound etc.

## LDAP Filter String From Tools

These are some common filters used by the recon tools (non-exchausted), some of them already mentioned by [Falcon Force](https://github.com/FalconForceTeam/FalconFriday/blob/master/Discovery/AD_Data_Collection_LDAP_Filter_Server_Side_MDI.md) and [Microsoft](https://techcommunity.microsoft.com/blog/microsoftdefenderatpblog/hunting-for-reconnaissance-activities-using-ldap-search-filters/824726). 

To harvest those LDAP filter strings, you may look into the source code and perform some regex or execute them in your test machine (with logging mode on).

Sometimes different EDR/tool will have different way on logging the LDAP query data, so just take certain keywords or minor changes from the `LDAP Filter String` column when perform searches in your environment. e.g. `UserAccountControl:1.2.840.113556.1.4.803:=2` to `UserAccountControl&2`

| Tools | LDAP Filter String |
|---|---|
| AD Explorer | objectGUID=* |
| Sharphound | (schemaIDGUID=*)<br>(&(objectclass=computer)(userAccountControl&8192))<br>(\|(samAccountType=805306368)(samAccountType=805306369)(objectclass=organizationalUnit))<br>(\|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))<br>(samAccountType=805306368)(samAccountType=805306369) |
| enum_ad_user_comments (Metasploit) | (&(&(objectCategory=person)(objectClass=user))(\|(description=\*pass\*)(comment=\*pass\*))) |
| enum_ad_computers (Metasploit) | (&(objectCategory=computer)(operatingSystem=\*server\*)) |
| enum_ad_groups (Metasploit) | (&(objectClass=group)) |
| enum_ad_managedby_groups (Metasploit) | (&(objectClass=group)(managedBy=\*))<br>(&(objectClass=group)(managedBy=\*)(groupType:1.2.840.113556.1.4.803:=2147483648)) |
| Get-NetComputer (PowerView) | (&(sAMAccountType=805306369)(dnshostname=\*)) |
| Get-NetUser-Users (Powerview) | &(samAccountType=805306368)(samAccountName=\*) |
| Get-NetUser-SPNs (Powerview) | &(samAccountType=805306368)(servicePrincipalName=\*) |
| Get-DFSshareV2 (Powerview) | (&(objectClass=msDFS-Linkv2)) |
| Get-NetOU (PowerView) | (&(objectCategory=organizationalUnit)(name=*)) |
| Get-DomainSearcher (Empire) | (samAccountType=805306368) |
| Kerberoast Default (Rubeus) | (sAMAccountType=805306368)(servicePrincipalName=*)(!(sAMAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))) |
| Kerberoast RC4 (Rubues) | (!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24) |
| Kerberoast AES (Rubeus) | (msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24) |
| Asreproast (Rubeus)| (&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)) |
| Accounts with Constrained Delegation configured to ghost SPN (Purple Knight) | (&(msDS-AllowedToDelegateTo=*)(!(userAccountControl&16777216))) |
| Constrained Delegation with allowed Protocol Tranisition / S4U2Self (Purple Knight) | (&(msds-allowedToDelegateTo=*)(userAccountControl>=16777216)(userAccountControl:1.2.840.113556.1.4.803:=16777216)) |
| Constrained delegation configured and protocol transition not configured (Purple Knight)| &(msds-allowedToDelegateTo=*)(!(userAccountControl:1.2.840.113556.1.4.803:=16777216)) |
| Domain controllers with Resource Based Constrain Delegation, RBCD (Purple Knight) | (& (msDS-AllowedToActOnBehalfOfOtherIdentity=*)(!(primaryGroupID=516)))|
| krbtgt account with Resource-Based Constrained Delegation enabled (PurpleKnight) | (&(msds-allowedtoactonbehalfofotheridentity=*)(objectsid=$domainSID-502)) |
| Dont require pre auth (Purple Knight) | (&(userAccountControl>=4194304)(userAccountControl&4194304) (objectCategory=CN=Person,CN=Schema,CN=Configuration,DC=,DC=,DC=,DC=net)) |
| Unconstrained Delegation (Purple Knight) | (&(servicePrincipalName=*)(& (userAccountControl>=524288)(userAccountControl\|524288)(!(userAccountControl\|8192))(objectClass=user))) |
| Abnormal Password Reset (PurpleKnight) | (&(samaccounttype=805306368)(pwdLastSet>=$pwdLastSetThreshold)(!(userAccountControl:1.2.840.113556.1.4.803:=2))) |
| Anonymous NSPI access to AD enabled (PurpleKnight) | (&(objectClass=nTDSService)(cn=Directory Service)(dSHeuristics=*)) |
| Getting List of DC (PurpleKnight, Zerologon vulnerability) | (&(objectCategory=computer)(dnshostname=*)(\|(primaryGroupID=516)(primaryGroupID=521))) |
| Account no require password (PingCastle) | (&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)) |
| Generate user data ([PingCastle](https://github.com/netwrix/pingcastle/blob/master/Healthcheck/HealthcheckAnalyzer.cs#L484C29-L484C40)) | (\|(&(objectClass=user)(objectCategory=person))(objectcategory=msDS-GroupManagedServiceAccount)(objectcategory=msDS-ManagedServiceAccount)) |
| Details devices need to register with Entra ID ([PingCastle](https://smbtothecloud.com/hybrid-device-join-what-happens-behind-the-scenes/)) | (name=62a0ff2e-97b9-4513-943f-0d221bd30080) |
| Microsoft Entra Kerberos server objects (PingCastle) | (name=900274c4-b7d2-43c8-90ee-00a9f650e335) |
| SID history for groups (PingCastle) | (&(sidhistory=*)(\|(\|(\|(objectClass=posixGroup)(objectClass=groupOfUniqueNames))(objectClass=groupOfNames))(objectClass=group))) |
| Group Policy Creator Owners group, S-1-5-32-36 (PingCastle) | (\|(objectSid=\01\02\00\00\00\00\00\05\20\00\00\00\24\02\00\00)(sidhistory=\01\02\00\00\00\00\00\05\20\00\00\00\24\02\00\00)) |
| Administrator group, S-1-5-32-544 (PingCastle) | (\|(objectSid=\01\02\00\00\00\00\00\05\20\00\00\00\20\02\00\00)(sidhistory=\01\02\00\00\00\00\00\05\20\00\00\00\20\02\00\00)) |
| Backup operators, S-1-5-32-551 (PingCastle) | (\|(objectSid=\01\02\00\00\00\00\00\05\20\00\00\00\27\02\00\00)(sidhistory=\01\02\00\00\00\00\00\05\20\00\00\00\27\02\00\00)) |

## Others LDAP Filter String
| Items | LDAP Filter String |
|---|---|
| Domain admin | (&(\|(objectClass=user)(objectClass=group)) (objectSid=S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-512) )|
| Password never expired | (userAccountControl:1.2.840.113556.1.4.803:=65536) |
| Password expired within a period | (pwdlastset>=FIRST_TIME)(pwdlastset<=LAST_TIME) |
| Search all domain controllers | &(objectCategory=computer)(userAccountControl: 1.2.840.113556.1.4.803:=8192) |

## sAMAccountType (Credits to ChatGPT)
| Value | Type | Description |
|---|---|---|
| 805306368 | Domain Object | Base domain object for a domain |
| 805306369	| User Object |	A regular user account or service account |
| 805306370	| Group Object | A security or distribution group |
| 805306371	| Non-Security Group | Object	A distribution group (non-security) |
| 805306372	| Computer Object |	Represents a domain-joined computer |
| 805306373 | Trust Account	| Used for domain trust relationships |

## Side Notes
`UserAccountControl:1.2.840.113556.1.4.803:=2` can be represent as `UserAccountControl&2` as some EDR will simplify the data for storage optimization.

`msDS-AllowedToDelegateTo=*` attribute contains the list of services to which the account is allowed to delegate credentials.

`(!(userAccountControl&16777216))` excludes accounts that have the TrustedToAuthForDelegation / Protocol Transition is not configured.

`(msDS-AllowedToActOnBehalfOfOtherIdentity=*)` attribute specifies which service accounts or systems are permitted to act on behalf of users to access the target resource.

`(!(primaryGroupID=516))` ensures domain controllers are not included.

`(userAccountControl|524288)` corresponds to the `TRUSTED_FOR_DELEGATION` flag in the `userAccountControl` attribute.

## References
[Falcon Force](https://github.com/FalconForceTeam/FalconFriday/blob/master/Discovery/AD_Data_Collection_LDAP_Filter_Server_Side_MDI.md)\
[Microsoft](https://techcommunity.microsoft.com/blog/microsoftdefenderatpblog/hunting-for-reconnaissance-activities-using-ldap-search-filters/824726)\
[r3d-buck3t](https://medium.com/r3d-buck3t/how-to-abuse-resource-based-constrained-delegation-to-gain-unauthorized-access-36ac8337dd5a)\
[PentestLab](https://pentestlab.blog/2022/03/21/unconstrained-delegation/)\
[csandker](https://csandker.io/2020/02/15/KerberosDelegationAReferenceOverview.html)