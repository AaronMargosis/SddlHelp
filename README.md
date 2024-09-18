# SddlHelp

**SddlHelp.exe** helps with writing and understanding Security Descriptor Definition Language (SDDL), and how to do so for a variety of object types.
(SDDL is a concise and portable textual representation of Windows security descriptors.)

SDDL identifies well-known entities with a two-letter code, such as `BA` for (US-English localized) `BUILTIN\Administrators` and `SY` for the System account.
The `-sid` option takes SIDs and/or those two-letter codes and for each reports the two-letter code (if there is one), the SID, and the localized name.

SDDL defines permissions with a hexadecimal mask or a series of zero or more two-letter codes, the interpretation of
which are object-dependent. The `-rights` option takes one or more object types and lists the permissions associated
with those object types, along with the corresponding hexadecimal mask, and two-letter code (if there is one).

Finally, the `-translate` option takes an SDDl string and converts it to a (more) human-readable representation,
with object-specific permissions if an object type is specified. The SDDL string should usually be quoted, especially
if the tool is executed from a PowerShell session.

SDDL documentation: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language

## Command-line syntax
```
SddlHelp.exe  -sid sidSpec [...]
SddlHelp.exe  -rights objType [...]
SddlHelp.exe  -translate sddlString [objType]


With "-sid", "sidSpec" is one or more SIDs or SDDL string SID codes; examples:
    SddlHelp.exe -sid BA
    SddlHelp.exe -sid S-1-5-18
    SddlHelp.exe -sid S-1-1-0 LS BU

With "-rights", "objType" is one or more of these:
    sddl      Listing of all SDDL two-letter access rights codes and name of constant
    ntds      Mapping of AD Directory Services constants to defined SDDL codes
    file      Mapping of file permission constants to defined SDDL codes
    dir       Mapping of directory (file system) permission constants to defined SDDL codes
    pipe      Mapping of pipe permission constants to defined SDDL codes
    key       Mapping of registry key permission constants to defined SDDL codes
    service   Mapping of service permission constants to defined SDDL codes
    scm       Mapping of service control manager permission constants to defined SDDL codes
    process   Mapping of process permission constants to defined SDDL codes
    thread    Mapping of thread permission constants to defined SDDL codes
    evt       Mapping of Windows event log permission constants to defined SDDL codes
    share     Mapping of file share permission constants to defined SDDL codes
    com       Mapping of COM permission constants to defined SDDL codes
    winsta    Mapping of window station permission constants to defined SDDL codes
    desktop   Mapping of desktop permission constants to defined SDDL codes
    section   Mapping of section permission constants to defined SDDL codes
    filemap   Mapping of file mapping permission constants to defined SDDL codes
    token     Mapping of token permission constants to defined SDDL codes
    standard  Mapping of standard and generic permission constants to defined SDDL codes
  Examples:
    SddlHelp.exe -rights key
    SddlHelp.exe -rights file standard | sort

With "-translate", "sddlString" is an SDDL string and optional "objType" is an objType listed above.
  Examples:
    SddlHelp.exe -translate "O:SYD:PAI(D;;CC;;;WD)(A;;0x1200a9;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)" dir
    SddlHelp.exe -translate "O:BAD:(A;CI;KA;;;SY)(A;CI;RCWD;;;BA)S:AINO_ACCESS_CONTROL" key
```

## Sample outputs

### -sid
```
PS C:\> SddlHelp.exe -sid S-1-1-0 LS BU
WD  S-1-1-0        Everyone
LS  S-1-5-19       NT AUTHORITY\LOCAL SERVICE
BU  S-1-5-32-545   BUILTIN\Users
```

### -rights
```
PS C:\> SddlHelp.exe -rights file standard | sort
0x00000001  CC  FILE_READ_DATA
0x00000002  DC  FILE_WRITE_DATA
0x00000004  LC  FILE_APPEND_DATA
0x00000008  SW  FILE_READ_EA
0x00000010  RP  FILE_WRITE_EA
0x00000020  WP  FILE_EXECUTE
0x00000080  LO  FILE_READ_ATTRIBUTES
0x00000100  CR  FILE_WRITE_ATTRIBUTES
0x00010000  SD  DELETE
0x00020000  RC  READ_CONTROL
0x00040000  WD  WRITE_DAC
0x00080000  WO  WRITE_OWNER
0x000f0000      STANDARD_RIGHTS_REQUIRED
0x00100000      SYNCHRONIZE
0x00120089  FR  FILE_GENERIC_READ
0x001200a0  FX  FILE_GENERIC_EXECUTE
0x00120116  FW  FILE_GENERIC_WRITE
0x001f01ff  FA  FILE_ALL_ACCESS
0x01000000      ACCESS_SYSTEM_SECURITY
0x02000000      MAXIMUM_ALLOWED
0x10000000  GA  GENERIC_ALL
0x20000000  GX  GENERIC_EXECUTE
0x40000000  GW  GENERIC_WRITE
0x80000000  GR  GENERIC_READ
```

### -translate
```
PS C:\> SddlHelp.exe -translate "O:BAD:(A;CI;KA;;;SY)(A;CI;RCWD;;;BA)S:AINO_ACCESS_CONTROL" key
Control:  0x8814  (SE_DACL_PRESENT SE_SACL_PRESENT SE_SACL_AUTO_INHERITED SE_SELF_RELATIVE )
Owner:    BUILTIN\Administrators (S-1-5-32-544)
ACEs in DACL:  2
ACE 0.
    ACCESS_ALLOWED_ACE_TYPE
    SID:   NT AUTHORITY\SYSTEM (S-1-5-18)
    Flags: [00000002] CONTAINER_INHERIT_ACE
    Perms: [000f003f]
           KEY_ALL_ACCESS
ACE 1.
    ACCESS_ALLOWED_ACE_TYPE
    SID:   BUILTIN\Administrators (S-1-5-32-544)
    Flags: [00000002] CONTAINER_INHERIT_ACE
    Perms: [00060000]
           READ_CONTROL
           WRITE_DAC
NULL SACL
```