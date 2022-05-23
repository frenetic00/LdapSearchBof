# LDAP Search BOF
This project started when I was trying to figure out how to add functionality to TrustedSec's CS-Situatioinal-Awareness-BOF ldapsearch to decode sidHistory.
It has since evolved into a much bigger project to:
- Re-learn C
- Understanding how to use the Win32 API
- Understand the LDAP protocol in more depth

None of the work is particularly new or novel.
This code is heavily based on the work by Trustedsec's CS-Situational-Awareness-BOF ldapsearch and various other sources across the internet.
The code structure is slightly different and there are some additional features in this version which are now part of Trustedsec's ldapsearch (pending pull), such as the ability to read ntSecurityDescriptor.
I've provided links to various internet resources which I found useful while I was writing the code.
Some of my comments may not be 100% accurate but I hope they prove useful to anyone trying to get to grips with C and Win32 API programming.

## Additional Features
- CNA script for lazy search queries (see help) (some not opsec)
- LDAP epoch decode
- Zulu time decode
- UAC decode
- Authenticate as a different user
- SidHistory decode
- Extended LDAP searching with paging
- Fallback mechanism (v3 Extended and Paging / v3 Extended only / v3 Paging Only / v2
- LDAP v3 whoami Check
- Extended LDAP search pre-programmed with LDAP_OID_SD_FLAGS control set appropriately so any user can request ntSecurityDescriptor (owner, group, and DACL, SACL isn't returned as this requires DA level privileges)
- Sliver support

## Credits
Thanks to Trustedsec's CS-Situational-Awareness-BOF for insipring this project.
Various code snippets across the internet have helped me write this code which I've referenced in the source.
Thanks to [LarryCheech](https://github.com/LarryCheech) and [magrath3an](https://github.com/magrath3an) for testing the code and encouraging the scope creep.
