// This code mostly follows the example from Windows and Situational Awareness bof
// https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/searching-a-directory
// https://github.com/trustedsec/CS-Situational-Awareness-BOF/

// INFO: Loading the a function from a DLL
// https://docs.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_init
// The function according to windows is defined as
// WINLDAPAPI LDAP* LDAPAPI ldap_init(PSTR, ULONG);
//
// Looking at the header file for this function
// https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/um/Winldap.h
// We can see that WINLDAPAPI is defined as DECLSPEC_IMPORT
// https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/um/Winldap.h#L71
//
// DECLSPEC_IMPORT is a macro defind in Ntdef.h which resolves to __declspec(import)
// It's a sorage-class specifier that tells the compiler that a function, object, or data
// is defind in an external DLL
// https://docs.microsoft.com/en-us/cpp/cpp/declspec?view=msvc-170
// https://stackoverflow.com/questions/8863193/what-does-declspecdllimport-really-mean
//
// LDAPAPI is also defined in the header file as __cdecl
// https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/um/Winldap.h#L78
// __cdecl defines how arguments are put ont he stack at the assembler level and is typically
// the default calling convention and includes stack cleanup code, the alternative would be __stdcall
// https://docs.microsoft.com/en-us/cpp/cpp/cdecl?view=msvc-170
// https://stackoverflow.com/questions/56471788/what-do-cdecl-and-void-mean
//
// WINLDAPAPI LDAP* LDAPAPI ldap_init(PSTR, ULONG);
// Therefore ranslates to
// __declspec(dllimport) LDAP* __cdecl ldap_init(PSTR, ULONG);
//
// From left to right:
// Load in function from DLL
// It returns an LDAP pointer
// Use the standard calling convention
// The function to load is ldap_init
// It takes 2 arguments of type PSTR and ULONG
//
// Windows documentation on functions found in the C standard library isn't very clear
// The C Standard library on Windows is defined in Msvcrt.lib
// https://docs.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features?view=msvc-170
// Functions in this library can be loaded with any of the methods described above.
//
// Beacon Object File (BOF) Dynamic Function Resolution (DFR)
// The convention to load in a library within the BOF should be LIBRARY$FUNTION
// When we import DLLs a relocation record  will be populated within the compiled object's relocation table
// This can be seen with
// x86_64-w64-mingw-objdump -r myobject.x64.o
// relocation records are information about addressses referenced in the object file that the linker must adjust
// once it know the final memory allocation.
// In the case of a BOF, Becaon is acting like the linker and the loader of an object
// https://youtu.be/gfYswA_Ronw?t=393
// https://youtu.be/gfYswA_Ronw?t=770
//
// When the beacon loads in a BOF it reads the relocation table and relies on the LIBRARY$FUNTION convention
// to find the address of specific functions in memory.
// We can assume at this point that beacon uses LoadLibraryA and GetModuleHandle to return a function pointer
// because they don't have to be loaded using BOF DFR or any other means
// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm

// Import API's
#ifdef BOF

// These were added to allow the bof to work with COFFLoader (Sliver)
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA (LPCSTR lpLibFileName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);

// Differs from CS Situational Awareness BOF to avoid having to call
// string manipulation fuctions which won't be available if we choose
// to avoid DFR. Theoretically APIs can be loaded with this function
// however this increases the number of strings in the output object
// but the difference is probably negligable
FARPROC loadApi(LPCSTR lib, LPCSTR func) {
    FARPROC fp = NULL;

    HMODULE hLibrary = NULL;
    hLibrary = KERNEL32$LoadLibraryA(lib);
    if (hLibrary)
    {
        fp = KERNEL32$GetProcAddress(hLibrary, func);
    }

    if (fp == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Load library failed %s %s\n", lib, func);
    }

    return fp;
}

// BOF DFR

// SECUR32
WINBASEAPI BOOLEAN WINAPI SECUR32$GetUserNameExA(int NameFormat, LPSTR lpNameBuffer, PULONG nSize);

// MSVCRT
// C Runtime and standard library functions
// https://docs.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features?view=msvc-170
WINBASEAPI int __cdecl MSVCRT$vsnprintf(char *__restrict__ d, size_t n, const char *__restrict__ format, va_list arg);
DECLSPEC_IMPORT PCHAR __cdecl MSVCRT$strstr(const char *haystack, const char *needle);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *string1, const char *string2);
WINBASEAPI char *__cdecl MSVCRT$strncpy(char * strDest, const char *strSource, size_t count);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t _NumOfElements, size_t _SizeOfElements);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void *__restrict__ _Dst, const void *__restrict__ _Src, size_t _MaxCount);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
DECLSPEC_IMPORT __int64 __cdecl MSVCRT$_strtoi64(const char *strSource, char **endptr, int base);
WINBASEAPI unsigned long __cdecl MSVCRT$strtoul(const char *strSource, char **endptr, int base);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strtok(char *strToken, const char *strDelimit);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char *str);

// KERNEL32
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI void *WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
WINBASEAPI BOOL KERNEL32$FileTimeToSystemTime(const FILETIME *lpFileTIme, LPSYSTEMTIME lpSystemTime);

// NETAPI32
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameA(LPVOID, LPVOID, LPVOID, LPVOID, ULONG, LPVOID);
WINBASEAPI DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);

// RPCRT4
RPCRTAPI RPC_STATUS RPC_ENTRY RPCRT4$UuidToStringA(UUID *Uuid,RPC_CSTR *StringUuid);
RPCRTAPI RPC_STATUS RPC_ENTRY RPCRT4$RpcStringFreeA(RPC_CSTR *String);

// ADVAPI
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID Sid, LPSTR *StringSid);
WINADVAPI BOOL WINAPI ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorA(PSECURITY_DESCRIPTOR SecurityDescriptor, DWORD RequestedSDRevision, SECURITY_INFORMATION SecurityInformation, LPSTR *StringSecurityDescriptor, PULONG StringSecurityDescriptorLen);

// WLDAP32 - Dynamic Function Resolution
//WINLDAPAPI LDAP *LDAPAPI WLDAP32$ldap_init(PSTR, ULONG);
//WINLDAPAPI ULONG LDAPAPI WLDAP32$LdapGetLastError(VOID);
//WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP *);
//WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_set_option(LDAP *ld, int option, const void *invalue);
//WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_connect(LDAP *ld, struct l_timeval *timeout);
//WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_bind_s(LDAP *ld, const PSTR dn, const PCHAR cred, ULONG method);
//WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_search_s(LDAP *ld, PSTR base, ULONG scope, PSTR filter, PZPSTR attrs,
//                                               ULONG attrsonly, PLDAPMessage *res);
//WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_msgfree(LDAPMessage *res);
//WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_count_entries(LDAP *ld, LDAPMessage *res);
//WINLDAPAPI LDAPMessage *LDAPAPI WLDAP32$ldap_first_entry(LDAP *ld, LDAPMessage *res);
//WINLDAPAPI LDAPMessage *LDAPAPI WLDAP32$ldap_next_entry(LDAP *ld, LDAPMessage *entry);
//WINLDAPAPI PCHAR LDAPAPI WLDAP32$ldap_first_attribute(LDAP *ld, LDAPMessage *entry, BerElement **ptr);
//WINLDAPAPI PCHAR LDAPAPI WLDAP32$ldap_next_attribute(LDAP *ld, LDAPMessage *entry, BerElement *ptr);
//WINLDAPAPI VOID LDAPAPI WLDAP32$ldap_memfree(PCHAR block);
//WINLDAPAPI PCHAR *LDAPAPI WLDAP32$ldap_get_values(LDAP *ld, LDAPMessage *entry, const PSTR attr);
//WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_count_values(PCHAR *vals);
//WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_value_free(PCHAR *vals);
//WINLDAPAPI VOID LDAPAPI WLDAP32$ber_free(BerElement *pBerElement, INT fbuf);
//WINLDAPAPI struct berval **LDAPAPI WLDAP32$ldap_get_values_len(LDAP *ExternalHandle,LDAPMessage *Message,const PCHAR attr);
//WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_value_free_len(struct berval **vals);

// WLDAP32 - loadApi() typedefs
typedef LDAP *LDAPAPI (*ldap_init_t)(PSTR, ULONG);
typedef LDAP *LDAPAPI (*ldap_sslinit_t)(PSTR HostName, ULONG PortNumber, int secure);
typedef ULONG LDAPAPI (*LdapGetLastError_t)(VOID);
typedef ULONG LDAPAPI (*ldap_unbind_t)(LDAP *);
typedef ULONG LDAPAPI (*ldap_set_option_t)(LDAP *ld, int option, const void *invalue);
typedef ULONG LDAPAPI (*ldap_connect_t)(LDAP *ld, struct l_timeval *timeout);
typedef ULONG LDAPAPI (*ldap_bind_s_t)(LDAP *ld, const PSTR dn, const PCHAR cred, ULONG method);
typedef ULONG LDAPAPI (*ldap_search_s_t)(LDAP *ld, PSTR base, ULONG scope, PSTR filter, PZPSTR attrs,
                                               ULONG attrsonly, PLDAPMessage *res);
typedef ULONG LDAPAPI (*ldap_msgfree_t)(LDAPMessage *res);
typedef ULONG LDAPAPI (*ldap_count_entries_t)(LDAP *ld, LDAPMessage *res);
typedef LDAPMessage *LDAPAPI (*ldap_first_entry_t)(LDAP *ld, LDAPMessage *res);
typedef LDAPMessage *LDAPAPI (*ldap_next_entry_t)(LDAP *ld, LDAPMessage *entry);
typedef PCHAR LDAPAPI (*ldap_first_attribute_t)(LDAP *ld, LDAPMessage *entry, BerElement **ptr);
typedef PCHAR LDAPAPI (*ldap_next_attribute_t)(LDAP *ld, LDAPMessage *entry, BerElement *ptr);
typedef VOID LDAPAPI (*ldap_memfree_t)(PCHAR block);
typedef PCHAR *LDAPAPI (*ldap_get_values_t)(LDAP *ld, LDAPMessage *entry, const PSTR attr);
typedef ULONG LDAPAPI (*ldap_count_values_t)(PCHAR *vals);
typedef ULONG LDAPAPI (*ldap_value_free_t)(PCHAR *vals);
typedef struct berval **LDAPAPI (*ldap_get_values_len_t)(LDAP *ExternalHandle,LDAPMessage *Message,const PCHAR attr);
typedef ULONG LDAPAPI (*ldap_value_free_len_t)(struct berval **vals);
typedef PLDAPSearch LDAPAPI (*ldap_search_init_page_t)(PLDAP ExternalHandle, const PCHAR DistinguishedName, ULONG ScopeOfSearch, const PCHAR SearchFilter, PCHAR AttributeList[], ULONG AttributesOnly, PLDAPControlA *ServerControls, PLDAPControlA *ClientControls, ULONG PageTimeLimit, ULONG TotalSizeLimit, PLDAPSortKeyA *SortKeys);
typedef ULONG LDAPAPI (*ldap_search_abandon_page_t)(PLDAP ExternalHandle, PLDAPSearch SearchBlock);
typedef ULONG LDAPAPI (*ldap_get_next_page_s_t)(PLDAP ExternalHandle, PLDAPSearch SearchHandle, struct l_timeval *timeout, ULONG PageSize, ULONG *TotalCount, LDAPMessage **Results);
typedef ULONG LDAPAPI (*ldap_extended_operation_sA_t)(LDAP *ExternalHandle, PSTR Oid, struct berval *Data, PLDAPControlA *ServerControls, PLDAPControlA *ClientControls, PCHAR *ReturnedOid, struct berval **ReturnedData);
typedef ULONG LDAPAPI (*ldap_parse_result_t)(LDAP *connection, LDAPMessage *ResultMessage, ULONG *ReturnCode, PSTR *MatchedDNs, PSTR *ErrorMessage, PSTR **Referrals, PLDAPControlA **ServerControls, BOOLEAN Freeit);
typedef ULONG LDAPAPI (*ldap_search_ext_s_t)(LDAP *ld, PSTR base, ULONG scope, PSTR filter, PZPSTR attrs, ULONG attrsonly, PLDAPControlA *ServerControls, PLDAPControlA *ClientControls, struct l_timeval *timeout, ULONG SizeLimit, PLDAPMessage *res);
typedef ULONG LDAPAPI (*ldap_create_page_control_t)(LDAP *ld, ULONG PageSize, struct berval *cookie, UCHAR IsCritical, PLDAPControlA *Control);
typedef ULONG LDAPAPI (*ldap_control_free_t)(LDAPControlA *Control);
typedef ULONG LDAPAPI (*ldap_controls_free_t)(LDAPControlA **Control);
typedef ULONG LDAPAPI (*ldap_parse_page_control_t)(PLDAP ExternalHandle, PLDAPControlA *ServerControls, ULONG *TotalCount, struct berval **Cookie);
typedef VOID LDAPAPI (*ber_free_t)(BerElement *pBerElement, INT fbuf);
typedef BerElement *LDAPAPI (*ber_alloc_t_t)(INT options);
typedef INT LDAPAPI (*ber_printf_t)(BerElement *pBerElement, PSTR fmt, ...);
typedef INT LDAPAPI (*ber_flatten_t)(BerElement *pBerElement, PBERVAL *pBerVal);
typedef VOID LDAPAPI (*ber_bvfree_t)(BERVAL *pBerVal);

// WLDAP32 - loadAPI() define Standard
#define WLDAP32$ldap_init ((ldap_init_t)loadApi("WLDAP32", "ldap_init"))
#define WLDAP32$ldap_sslinit ((ldap_sslinit_t)loadApi("WLDAP32", "ldap_sslinit"))
#define WLDAP32$LdapGetLastError ((LdapGetLastError_t)loadApi("WLDAP32", "LdapGetLastError"))
#define WLDAP32$ldap_unbind ((ldap_unbind_t)loadApi("WLDAP32", "ldap_unbind"))
#define WLDAP32$ldap_set_option ((ldap_set_option_t)loadApi("WLDAP32", "ldap_set_option"))
#define WLDAP32$ldap_connect ((ldap_connect_t)loadApi("WLDAP32", "ldap_connect"))
#define WLDAP32$ldap_bind_s ((ldap_bind_s_t)loadApi("WLDAP32", "ldap_bind_s"))
#define WLDAP32$ldap_search_s ((ldap_search_s_t)loadApi("WLDAP32", "ldap_search_s"))
#define WLDAP32$ldap_msgfree ((ldap_msgfree_t)loadApi("WLDAP32", "ldap_msgfree"))
#define WLDAP32$ldap_count_entries ((ldap_count_entries_t)loadApi("WLDAP32", "ldap_count_entries"))
#define WLDAP32$ldap_first_entry ((ldap_first_entry_t)loadApi("WLDAP32", "ldap_first_entry"))
#define WLDAP32$ldap_next_entry ((ldap_next_entry_t)loadApi("WLDAP32", "ldap_next_entry"))
#define WLDAP32$ldap_first_attribute ((ldap_first_attribute_t)loadApi("WLDAP32", "ldap_first_attribute"))
#define WLDAP32$ldap_next_attribute ((ldap_next_attribute_t)loadApi("WLDAP32", "ldap_next_attribute"))
#define WLDAP32$ldap_memfree ((ldap_memfree_t)loadApi("WLDAP32", "ldap_memfree"))
#define WLDAP32$ldap_get_values ((ldap_get_values_t)loadApi("WLDAP32", "ldap_get_values"))
#define WLDAP32$ldap_count_values ((ldap_count_values_t)loadApi("WLDAP32", "ldap_count_values"))
#define WLDAP32$ldap_value_free ((ldap_value_free_t)loadApi("WLDAP32", "ldap_value_free"))
#define WLDAP32$ldap_get_values_len ((ldap_get_values_len_t)loadApi("WLDAP32", "ldap_get_values_len"))
#define WLDAP32$ldap_value_free_len ((ldap_value_free_len_t)loadApi("WLDAP32", "ldap_value_free_len"))
#define WLDAP32$ldap_search_init_page ((ldap_search_init_page_t)loadApi("WLDAP32", "ldap_search_init_page"))
#define WLDAP32$ldap_search_abandon_page ((ldap_search_abandon_page_t)loadApi("WLDAP32", "ldap_search_abandon_page"))
#define WLDAP32$ldap_get_next_page_s ((ldap_get_next_page_s_t)loadApi("WLDAP32", "ldap_get_next_page_s"))
#define WLDAP32$ldap_extended_operation_sA ((ldap_extended_operation_sA_t)loadApi("WLDAP32", "ldap_extended_operation_sA"))
#define WLDAP32$ldap_parse_result ((ldap_parse_result_t)loadApi("WLDAP32", "ldap_parse_result"))
#define WLDAP32$ldap_search_ext_s ((ldap_search_ext_s_t)loadApi("WLDAP32", "ldap_search_ext_s"))
#define WLDAP32$ldap_create_page_control ((ldap_create_page_control_t)loadApi("WLDAP32", "ldap_create_page_control"))
#define WLDAP32$ldap_control_free ((ldap_control_free_t)loadApi("WLDAP32", "ldap_control_free"))
#define WLDAP32$ldap_controls_free ((ldap_controls_free_t)loadApi("WLDAP32", "ldap_controls_free"))
#define WLDAP32$ldap_parse_page_control ((ldap_parse_page_control_t)loadApi("WLDAP32", "ldap_parse_page_control"))
#define WLDAP32$ber_free ((ber_free_t)loadApi("WLDAP32", "ber_free"))
#define WLDAP32$ber_alloc_t ((ber_alloc_t_t)loadApi("WLDAP32", "ber_alloc_t"))
#define WLDAP32$ber_printf ((ber_printf_t)loadApi("WLDAP32", "ber_printf"))
#define WLDAP32$ber_flatten ((ber_flatten_t)loadApi("WLDAP32", "ber_flatten"))
#define WLDAP32$ber_bvfree ((ber_bvfree_t)loadApi("WLDAP32", "ber_bvfree"))

#else

// Some API's are specific to the BOF implementation and
// therefore have been ommited if not required to create an exe

// SECUR32
#define SECUR32$GetUserNameExA GetUserNameExA

// MSVCRT
#define MSVCRT$vsnprintf vsnprintf
#define MSVCRT$strstr strstr
#define MSVCRT$strcmp strcmp
#define MSVCRT$strncpy strncpy
#define MSVCRT$_strtoi64 _strtoi64
#define MSVCRT$strtoul strtoul
#define MSVCRT$strtok strtok
#define MSVCRT$strlen strlen

// KERNEL32
#define KERNEL32$GetLastError GetLastError
#define KERNEL32$LocalFree LocalFree
#define KERNEL32$FileTimeToSystemTime FileTimeToSystemTime

// NETAPI32
#define NETAPI32$DsGetDcNameA DsGetDcNameA
#define NETAPI32$NetApiBufferFree NetApiBufferFree

// RPCRT4
#define RPCRT4$UuidToStringA UuidToStringA
#define RPCRT4$RpcStringFreeA RpcStringFreeA

// ADVAPI
#define ADVAPI32$ConvertSidToStringSidA ConvertSidToStringSidA
#define ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorA ConvertSecurityDescriptorToStringSecurityDescriptorA

// WLDAP32
#define WLDAP32$ldap_init ldap_init
#define WLDAP32$ldap_sslinit ldap_sslinit
#define WLDAP32$LdapGetLastError GetLastError
#define WLDAP32$ldap_unbind ldap_unbind
#define WLDAP32$ldap_set_option ldap_set_option
#define WLDAP32$ldap_connect ldap_connect
#define WLDAP32$ldap_bind_s ldap_bind_s
#define WLDAP32$ldap_search_s ldap_search_s
#define WLDAP32$ldap_msgfree ldap_msgfree
#define WLDAP32$ldap_count_entries ldap_count_entries
#define WLDAP32$ldap_first_entry ldap_first_entry
#define WLDAP32$ldap_next_entry ldap_next_entry
#define WLDAP32$ldap_first_attribute ldap_first_attribute
#define WLDAP32$ldap_next_attribute ldap_next_attribute
#define WLDAP32$ldap_memfree ldap_memfree
#define WLDAP32$ldap_get_values ldap_get_values
#define WLDAP32$ldap_count_values ldap_count_values
#define WLDAP32$ldap_value_free ldap_value_free
#define WLDAP32$ldap_get_values_len ldap_get_values_len
#define WLDAP32$ldap_value_free_len ldap_value_free_len
#define WLDAP32$ldap_search_init_page ldap_search_init_page
#define WLDAP32$ldap_search_abandon_page ldap_search_abandon_page
#define WLDAP32$ldap_get_next_page_s ldap_get_next_page_s
#define WLDAP32$ldap_extended_operation_sA ldap_extended_operation_sA
#define WLDAP32$ldap_parse_result ldap_parse_result
#define WLDAP32$ldap_search_ext_s ldap_search_ext_s
#define WLDAP32$ldap_create_page_control ldap_create_page_control
#define WLDAP32$ldap_control_free ldap_control_free
#define WLDAP32$ldap_controls_free ldap_controls_free
#define WLDAP32$ldap_parse_page_control ldap_parse_page_control
#define WLDAP32$ber_free ber_free
#define WLDAP32$ber_alloc_t ber_alloc_t
#define WLDAP32$ber_printf ber_printf
#define WLDAP32$ber_flatten ber_flatten
#define WLDAP32$ber_bvfree ber_bvfree

#endif
