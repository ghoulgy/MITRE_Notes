# LDAP PurpleKnight

Possible scripts that use LDAP query. The name of the scripts does tell about their functionality 😌.
You can check out those scripts and find out all the LDAP filter strings used.

This page will just put some items for `ADApi.ps1`.

```
ADApi.ps1
AAD_PrivilegedOnPremiseAndAAD.ps1
AAD_PrivilegedOnPremiseSyncedToAAD.ps1
AAD_RBCDOnSSOUser.ps1
AAD_SSOOldPwdLastSet.ps1
AbnormalPasswordRefresh.ps1
AccountsInCertPublishers.ps1
AdminPWNotChanged.ps1
AdminSDHolderInheritance.ps1
AdminSDHolderPermissionChange.ps1
AdminUsedRecently.ps1
AnonAccessonAD.ps1
AnonNSPIAccess.ps1
CertificatesNTAuthPermissions.ps1
CertificateTemplatesAreVulnerable.ps1
CertificateTemplatesPermissions.ps1
CertificateTemplatesWithSANAllowed.ps1
ChangesToAdminContextMenuPK.ps1
ChangesToDefaultSD.ps1
ChangesToDomainOrDCPolicies.ps1
CompObsoleteOS.ps1
ComputersInPrivilegedGroup.ps1
ComputerUserWithSPNUnconstrainedDelegation.ps1
ConstrainedDelegationToKRBTGT.ps1
DangerousTrustAttributeSet.ps1
DCShadowInUse.ps1
DelegateToGhostSPN.ps1
DisabledPrivilegedUsers.ps1
DnsZonesWithUnsecureUpdate.ps1
DwAdminSDExMaskSet.ps1
EnterpriseCAs.ps1
EphemeralAdmins.ps1
FGPPNotAppliedToAGroup.ps1
FSPInPrivilegedGroup.ps1
GMSAPasswordPermissions.ps1
GPOBadShortcut.ps1
GPOLogonScripts.ps1
GPOScheduledTasks.ps1
GPOUserRights.ps1
GuestAccountEnabled.ps1
InstallReplicaPermissions.ps1
KerberosGoldenTicket.ps1
LapsSearchFlagsNonDefault.ps1
LdapDenyList.ps1
NewObjects.ps1
NewPrivilegedUsers.ps1
NonPrivilegedObjectsWithAdminCount.ps1
NonStandardPGID.ps1
NonStandardSchemaPermissions.ps1
NoPGID.ps1
NTFRSSysvolReplication.ps1
ObjectsInPrivilegedGroupWithoutAdmincount.ps1
ObjectsWithConstrainedDelegation.ps1
ObjectsWithConstrainedDelegationDC.ps1
ObjectsWithLapsRead.ps1
ObjectsWithProtocolTranistion.ps1
ObjectsWithProtocolTransitionDC.ps1
OldPwdLastSet.ps1
OldPwdLastSetAdmin.ps1
OperatorsGroupsAreNotEmpty.ps1
PreWin2KGroup.ps1
PrimaryUsersWithSPN.ps1
PrimaryUsersWithSPNNotSupportingAES.ps1
PrivilegedGroupChanges.ps1
PrivilegedSPN.ps1
RBCD.ps1
RBCDOnDC.ps1
RBCDOnkrbtgt.ps1
RC4EnabledOnDC.ps1
RecentSIDHistoryChanges.ps1
ReplicationPermissions.ps1
RODCPrivilegedCreds.ps1
ShadowCredentials.ps1
SIDHistoryPrivilegedSID.ps1
SMBv1EnabledOnDCs.ps1
TrustPwdLastSet.ps1
WeakCertificateCipher.ps1
WeakGPOLinkingADSite.ps1
WeakGPOLinkingOnDCOU.ps1
WeakGPOLinkingOnDomain.ps1
ZeroLogonPK.ps1
```

## Enumerate Privilege Groups SID

Generic ldap filter string
```
(&(objectSid=$sid)(objectCategory=group))

e.g. 
(&(objectSid=S-1-5-32-551)(objectCategory=group))
```

Code snippet
```
$privilegedGroups = @("S-1-5-32-551","S-1-5-32-552","S-1-5-32-548","S-1-5-32-549","S-1-5-32-550","S-1-5-32-544",
    "$domainSID-512","$domainSID-516","$domainSID-521")

# Get a list of the groups DN
foreach ($sid in $privilegedGroups) {
    $groupObjectSearchParams = @{
        dnsDomain = $domain
        baseDN = $DN
        scope = "subtree"
        filter = "(&(objectSid=$sid)(objectCategory=group))"
    }
```

## Privilege group with description (Credits to ChatGPT)

| **SID**                             | **Group Name**                | **Description**                                                             |
|-------------------------------------|-------------------------------|-----------------------------------------------------------------------------|
| `S-1-5-32-551`                      | Backup Operators              | Members can override security restrictions for the purpose of backing up files. |
| `S-1-5-32-552`                      | Replicator                    | Supports file replication in a domain.                                      |
| `S-1-5-32-548`                      | Account Operators             | Members can create, modify, and delete accounts in the domain.              |
| `S-1-5-32-549`                      | Server Operators              | Members can administer servers in the domain.                               |
| `S-1-5-32-550`                      | Print Operators               | Members can manage printers in the domain.                                  |
| `S-1-5-32-544`                      | Administrators                | Full control over the system.                                               |
| `$domainSID-512`                    | Domain Admins                 | Members have administrative rights across the domain.                       |
| `$domainSID-516`                    | Domain Controllers            | Represents domain controllers in the domain.                                |
| `$domainSID-521`                    | Read-Only Domain Controllers  | Represents read-only domain controllers in the domain.                      |

## Privilege RID

Those RID description can refer to the table above.

Genric ldap query string
```
(|(primaryGroupID=$privilegedRID)(primaryGroupID=$privilegedRID)...)

e.g.
(|(primaryGroupID=551)(primaryGroupID=552)...)
```

Code Snippet
```
[void]$privilegedRIDs.AddRange(@("551","552","548","549","550","544","512","516","518","519","521"))

$primaryGroupFilter = "(|"
foreach($privilegedRID in $privilegedRIDs) {
    $primaryGroupFilter += "(primaryGroupID=$privilegedRID)"
}
$primaryGroupFilter += ")"
```

## Netbios
Gets the NetBIOS name of a given domain

```
(&(netbiosname=*)(dnsroot=$dnsDomain))

e.g.
(&(netbiosname=*)(dnsroot=test.domain))
```

## SPN Mappings
Get the services that map to the host SPN

```
(sPNMappings=*)
```

## Get linked OU
```
(&(|(objectClass=organizationalUnit)(objectClass=site)(objectClass=domain))(gplink=*))
```

## User Access Control (UAC) List

List of UAC value that used by the tool itself by combining them with other filter string.

| **Value**    | **Flag Name**                          | **Description**                              |
|--------------|---------------------------------------|----------------------------------------------|
| `1`          | Script                                | Logon script is executed.                    |
| `2`          | AccountDisabled                      | Account is disabled.                         |
| `8`          | HomeDirectoryRequired                | Home directory is required.                  |
| `16`         | AccountLockedOut                     | Account is locked out.                       |
| `32`         | PasswordNotRequired                  | No password is required for the account.     |
| `64`         | PasswordCannotChange                 | User cannot change the password.             |
| `128`        | EncryptedTextPasswordAllowed         | Encrypted text password is allowed.          |
| `256`        | TempDuplicateAccount                 | Account is a temporary duplicate account.    |
| `512`        | NormalAccount                        | Account is a default user account.           |
| `2048`       | InterDomainTrustAccount              | Account is for an inter-domain trust.        |
| `4096`       | WorkstationTrustAccount              | Account is for a computer/workstation trust. |
| `8192`       | ServerTrustAccount                   | Account is for a server trust.               |
| `65536`      | PasswordDoesNotExpire                | Password will not expire.                    |
| `131072`     | MnsLogonAccount                      | MNS (Message Queuing) logon account.         |
| `262144`     | SmartCardRequired                    | Smart card is required for login.            |
| `524288`     | TrustedForDelegation                 | Account is trusted for delegation.           |
| `1048576`    | AccountNotDelegated                  | Account cannot be delegated.                 |
| `2097152`    | UseDesKeyOnly                        | Only DES encryption is allowed for the account. |
| `4194304`    | DontRequirePreauth                   | Preauthentication is not required.           |
| `8388608`    | PasswordExpired                      | Password has expired.                        |
| `16777216`   | TrustedToAuthenticateForDelegation   | Trusted to authenticate for delegation.      |
| `33554432`   | NoAuthDataRequired                   | No authentication data is required.          |
| `67108864`   | PartialSecretsAccount                | Partial secrets for the account are allowed. |