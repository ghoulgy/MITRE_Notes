# LDAP (Rubeus)
Rubeus did LDAP search when performing certain activities like kerberoasting and Asreproasting.

## Rubeus krbtgt
User can specify user, encryption type and password last reset period into the LDAP query.

LDAP query build starts at [L457](https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/Roast.cs#L458) and the base LDAP query is `&(sAMAccountType=805306368)(servicePrincipalName=*)` as stated at [L527](https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/Roast.cs#L527)

### Users
Common query is to make sure the account is not disabled `(!(UserAccountControl:1.2.840.113556.1.4.803:=2))`

#### Specific User
Multiple User
```
(&(|(samAccountName=USER1)(samAccountName=USER2))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))
```

Single User
```
(samAccountName=USER)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))
```
#### No Specified User
```
(!(sAMAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))
```

### Encryption Type
Account supports **rc4opsec**, **AES128/256** or **no encryption**

#### Account Ticket Support Encrpytion rc4opsec
```
(!msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24)
```

### Password Reset Period
```
(pwdlastset>=FIRST_TIME)(pwdlastset<=LAST_TIME)
```

#### Account Ticket Encryption AES128/256
```
(msds-supportedencryptiontypes:1.2.840.113556.1.4.804:=24)
```

### Final LDAP Query
Final query will be formed at (L527)[https://github.com/GhostPack/Rubeus/blob/6ce95440c7ff8c6a458d6999d197cab58c66dac7/Rubeus/lib/Roast.cs#L527]

## Rubeus asreproast
Specific user at [L48](https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/Roast.cs#L48)
```
(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(samAccountName=USER))
```

No specific user
```
(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```


