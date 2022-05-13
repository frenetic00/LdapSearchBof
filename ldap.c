#include <windows.h>

#include "beacon.h"
#include <dsgetdc.h>
#include <errhandlingapi.h>
#include <heapapi.h>
#include <lm.h>
#include <rpc.h>
#include <sddl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winerror.h>
#include <winldap.h>

#include <winber.h>

// https://stackoverflow.com/a/46845072
#define SECURITY_WIN32
#include <secext.h>

#define USERNAME_BUFFER 512
#define MAX_ATTRIBUTES 100
#define LDAP_OID_SD_FLAGS "1.2.840.113556.1.4.801"
#define LDAP_OID_PAGED_RESULT "1.2.840.113556.1.4.319"
#define LDAP_OID_WHOAMI "1.3.6.1.4.1.4203.1.11.3"

// Load in Dynamic Function Resolution (DFR) or load functions with
// LoadLibraryA
#include "libs.h"

// Load function used for outputting data
#include "output.h"

// Free-for-all extended LDAP operation to fetch current user
void ldapWhoami(LDAP *ldapConnectionPtr)
{
    ULONG lRtn = 0;
    struct berval *pBV = NULL;

    lRtn = WLDAP32$ldap_extended_operation_sA(ldapConnectionPtr, LDAP_OID_WHOAMI, NULL, NULL, NULL, NULL, &pBV);
    if(lRtn == LDAP_SUCCESS) {
        commonPrintf("LDAP Whoami: %s\n", (PCHAR)((PBERVAL)pBV->bv_val)+2);
    }
    
    WLDAP32$ldap_memfree((PCHAR)pBV);
}   

// Parse an LDAP message
ULONG ldapParse(LDAP *ldapConnectionPtr, LDAPMessage *ldapMessage)
{
    // Loop through entries
    LDAPMessage *pEntry = NULL;
    ULONG entryCount = 0;
    BerElement *pBer = NULL;
    PCHAR pAttribute = NULL;
    PCHAR *pointersToValues = NULL;
    ULONG valueCount = 0;
    BOOL isSid = FALSE;
    BOOL isLdapFiletime = FALSE;
    BOOL isLdapYmd = FALSE;
    BOOL isGuid = FALSE;
    BOOL isUAC = FALSE;
    BOOL isDescriptor = FALSE;

    // Count entries in search
    ULONG searchEntryCount = WLDAP32$ldap_count_entries(ldapConnectionPtr, ldapMessage);
    if (searchEntryCount == -1)
    {
        commonPrintf("Count entiries failed: ERROR 0x%0lx\n", searchEntryCount);
        return 0;
    }

    for (entryCount = 0; entryCount < searchEntryCount; entryCount++)
    {
        // Get first / next entry in the ldap message
        if (!entryCount)
        {
            pEntry = WLDAP32$ldap_first_entry(ldapConnectionPtr, ldapMessage);
        }
        else
        {
            pEntry = WLDAP32$ldap_next_entry(ldapConnectionPtr, pEntry);
        }

        // Catch an empty entry
        if (pEntry == NULL)
        {
            commonPrintf("Failed to fetch entry\n");
            continue;
        }
        else
        {
            commonPrintf("-----------------\n");
        }

        // Parse attributes
        pAttribute = WLDAP32$ldap_first_attribute(ldapConnectionPtr, pEntry, &pBer);
        if (pAttribute == NULL)
        {
            commonPrintf("No attributes\n");
        }
        while (pAttribute != NULL)
        {
            isSid = isLdapFiletime = isLdapYmd = isGuid = isUAC = isDescriptor = FALSE;

            // Parse and print attribute
            // isSid
            if (MSVCRT$strcmp(pAttribute, "objectSid") == 0 ||
                    MSVCRT$strcmp(pAttribute, "sIDHistory") == 0)
            {
                isSid = TRUE;
            }
            
            if (MSVCRT$strcmp(pAttribute, "nTSecurityDescriptor") == 0)
            {
                isDescriptor = TRUE;
            }

            // isLdapFiletime
            if (MSVCRT$strcmp(pAttribute, "pwdLastSet") == 0 ||
                    MSVCRT$strcmp(pAttribute, "accountExpires") == 0 ||
                    MSVCRT$strcmp(pAttribute, "lastLogoff") == 0 ||
                    MSVCRT$strcmp(pAttribute, "lastLogon") == 0 ||
                    MSVCRT$strcmp(pAttribute, "LastPwdSet") == 0 ||
                    MSVCRT$strcmp(pAttribute, "lastLogonTimestamp") == 0 ||
                    MSVCRT$strcmp(pAttribute, "badPasswordTime") == 0)
            {
                isLdapFiletime = TRUE;
            }

            // isLdapYmd
            if (MSVCRT$strcmp(pAttribute, "whenCreated") == 0 ||
                    MSVCRT$strcmp(pAttribute, "whenChanged") == 0 ||
                    MSVCRT$strcmp(pAttribute, "dSCorePropagationData") == 0)
            {
                isLdapYmd = TRUE;
            }

            // isGuid
            if (MSVCRT$strcmp(pAttribute, "objectGUID") == 0)
            {
                isGuid = TRUE;
            }
            
            // isUAC
            if (MSVCRT$strcmp(pAttribute, "userAccountControl") == 0)
            {
                isUAC = TRUE;
            }

            commonPrintf("%s: ", pAttribute);

            // Parse and print value
            if(isSid || isGuid || isDescriptor)
            {
                // Ber values
                pointersToValues = (char **)WLDAP32$ldap_get_values_len(ldapConnectionPtr, pEntry, pAttribute);
            }
            else
            {
                // String values
                //pAttribute = (requestedAttribute) ? requestedAttribute : pAttribute;
                pointersToValues = WLDAP32$ldap_get_values(ldapConnectionPtr, pEntry, pAttribute);
            }

            if (pointersToValues == NULL)
            {
                commonPrintf("No attribute value\n");
            }
            else
            {
                valueCount = WLDAP32$ldap_count_values(pointersToValues);
                if (!valueCount)
                {
                    commonPrintf("Bad value list\n");
                }
                else
                {
                    // Loop through values
                    ULONG i;
                    for (i = 0; i < valueCount; i++)
                    {
                        // Prepare line ending
                        PCHAR strEnd = NULL;
                        if (valueCount == 1)
                        {
                            strEnd = "\n";
                        }
                        else
                        {
                            strEnd = (i == valueCount-1 ? "\n" : ", ");
                        }

                        if (isSid)
                        {
                            LPSTR sid = NULL;
                            PBERVAL value = (PBERVAL)pointersToValues[i];
                            ADVAPI32$ConvertSidToStringSidA((PSID)value->bv_val, &sid);
                            commonPrintf("%s%s", sid, strEnd);
                            KERNEL32$LocalFree(sid);
                        }
                        else if (isDescriptor)
                        {
                            LPTSTR sd;
                            ULONG sdLen;
                            PBERVAL valueS = (PBERVAL)pointersToValues[i];
                            ADVAPI32$ConvertSecurityDescriptorToStringSecurityDescriptorA((PSECURITY_DESCRIPTOR)valueS->bv_val, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sd, &sdLen);
                            commonPrintf("%s\n", sd);
                        }
                        else if (isLdapFiletime)
                        {
                            __int64 ldapFtInt = MSVCRT$_strtoi64(pointersToValues[i], NULL, 10);

                            SYSTEMTIME st = {0};
                            FILETIME ft = {(DWORD)ldapFtInt, ldapFtInt >> 32};
                            KERNEL32$FileTimeToSystemTime(&ft, &st);

                            commonPrintf("%s (%4d-%.2d-%.2d %.2d:%.2d:%.2d)%s", *pointersToValues, st.wYear, st.wMonth,
                                         st.wDay, st.wHour, st.wMinute, st.wSecond, strEnd);
                        }
                        else if (isLdapYmd)
                        {
                            char time[20] = {0};
                            char* s = pointersToValues[i];
                            char* d = time;

                            // Gross pointer arithmetic
                            MSVCRT$strncpy(d, s+0, 4);
                            MSVCRT$strncpy(d+5, s+4, 2);
                            MSVCRT$strncpy(d+8, s+6, 2);
                            MSVCRT$strncpy(d+11, s+8, 2);
                            MSVCRT$strncpy(d+14, s+10, 2);
                            MSVCRT$strncpy(d+17, s+12, 2);
                            time[4] = time[7] = '-';
                            time[10] = ' ';
                            time[13] = time[16] = ':';
                            commonPrintf("%s (%s Z)%s", pointersToValues[i], time, strEnd);
                        }
                        else if (isGuid)
                        {
                            RPC_CSTR guid = NULL;
                            PBERVAL value = (PBERVAL)pointersToValues[i];
                            RPCRT4$UuidToStringA((UUID *)value->bv_val, &guid);
                            commonPrintf("%s%s", guid, strEnd);
                            RPCRT4$RpcStringFreeA(&guid);
                        }
                        else if (isUAC)
                        {
                            //DWORD val = 4194336;
                            DWORD uac = MSVCRT$strtoul(pointersToValues[i], NULL, 10);
                            commonPrintf("%s ( ", pointersToValues[i]);

                            // https://overiq.com/c-programming-101/array-of-pointers-to-strings-in-c/
                            // http://woshub.com/decoding-ad-useraccountcontrol-value/
                            // Must specify array size and include a NULL entry at the end for it to work
                            // in Beacon
                            char *uacProp[28] = {
                                "SCRIPT",
                                "ACCOUNTDISABLE",
                                "-",
                                "HOMEDIR_REQUIRED",
                                "LOCKOUT",
                                "PASSWD_NOTREQD",
                                "PASSWD_CANT_CHANGE",
                                "ENCRYPTED_TEXT_PWD_ALLOWED",
                                "TEMP_DUPLICATE_ACCOUNT",
                                "NORMAL_ACCOUNT",
                                "-",
                                "INTERDOMAIN_TRUST_ACCOUNT",
                                "WORKSTATION_TRUST_ACCOUNT",
                                "SERVER_TRUST_ACCOUNT",
                                "-",
                                "-",
                                "DONT_EXPIRE_PASSWORD",
                                "MNS_LOGON_ACCOUNT",
                                "SMARTCARD_REQUIRED",
                                "TRUSTED_FOR_DELEGATION",
                                "NOT_DELEGATED",
                                "USE_DES_KEY_ONLY",
                                "DONT_REQ_PREAUTH",
                                "PASSWORD_EXPIRED",
                                "TRUSTED_TO_AUTH_FOR_DELEGATION",
                                "-",
                                "PARTIAL_SECRETS_ACCOUNT"
                            };

                            for (DWORD index=0; index<27; index++)
                            {
                                DWORD base = 2;
                                DWORD exp = index;
                                DWORD pow = 1;

                                if (exp == 0) 
                                {
                                    pow = 1;
                                }
                                else
                                {
                                    while (exp != 0) {
                                        pow *= base;
                                        --exp;
                                    }
                                }

                                if ((uac | pow) == uac)
                                {
                                    commonPrintf("%s ", uacProp[index]);
                                }
                            }
                            commonPrintf(") \n");
                        }
                        else
                        {
                            commonPrintf("%s%s", pointersToValues[i], strEnd);
                        }

                        // For loop can be replaced with this while loop
                        // Duplicate the pointer because other parts of the code
                        // relies on seeing values in pointersToValues
                        //PCHAR *p = pointersToValues;
                        //while(*p != NULL) {
                        //    commonPrintf("%s,", *p);
                        //    p++;
                        //}
                        //commonPrintf("\n");
                    }
                }
            }

            if (pointersToValues != NULL && isSid)
            {
                WLDAP32$ldap_value_free(pointersToValues);
            }
            else if (pointersToValues != NULL)
            {
                WLDAP32$ldap_value_free_len((PBERVAL *)pointersToValues);
            }
            pointersToValues = NULL;
            WLDAP32$ldap_memfree(pAttribute);
            pAttribute = WLDAP32$ldap_next_attribute(ldapConnectionPtr, pEntry, pBer);
        }

        if (pBer != NULL)
        {
            WLDAP32$ber_free(pBer, 0);
        }
        pBer = NULL;
    }

    return searchEntryCount;
}

LDAP* ldapConnect(ULONG version, char* pdc, char* domainDN, char* domain, char* username, char* password)
{
    LDAP* ldapConnectionPtr = NULL;
    
    ULONG lRtn = 0;
    
    // Set up credentials
    SEC_WINNT_AUTH_IDENTITY secIdent;
    
    // Initialise an LDAP session
    //commonPrintf("Initialise connection\n");
    ldapConnectionPtr = WLDAP32$ldap_init(pdc, 389);
    //ldapConnectionPtr = WLDAP32$ldap_sslinit(pdc, 636, 1);

    if (ldapConnectionPtr == NULL)
    {

        // Print the error
        // https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/return-values
        ULONG error = WLDAP32$LdapGetLastError();
        commonPrintf("init failed: ERROR 0x%x\n", error);

        // Free LDAP session handle as per the documentaton
        WLDAP32$ldap_unbind(ldapConnectionPtr);
        return NULL;
    }

    // Set LDAP session options
    // https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/session-options
    // Set protocol version
    lRtn = WLDAP32$ldap_set_option(ldapConnectionPtr, LDAP_OPT_PROTOCOL_VERSION, (const void *)&version);
    if (lRtn == LDAP_SUCCESS)
    {
        commonPrintf("Session will use v%i\n", version);
    }
    else
    {
        WLDAP32$ldap_unbind(ldapConnectionPtr);
        return NULL;
    }

    //void* referralOption = LDAP_OPT_ON;
    void* referralOption = LDAP_OPT_OFF;
    // Set Referrals
    lRtn = WLDAP32$ldap_set_option(ldapConnectionPtr, LDAP_OPT_REFERRALS, (const void *) &referralOption);
    if (lRtn == LDAP_SUCCESS)
    {
        commonPrintf("Referrals set to: %i\n", referralOption);
    }
    else
    {
        commonPrintf("Referrals fail\n");
        return NULL;
    }

    // Connect to the LDAP server
    lRtn = WLDAP32$ldap_connect(ldapConnectionPtr, NULL);
    if (lRtn == LDAP_SUCCESS)
    {
        //commonPrintf("Connection successful\n");
    }
    else
    {
        commonPrintf("Connection failed: ERROR 0x%x\n", lRtn);
        WLDAP32$ldap_unbind(ldapConnectionPtr);
        return NULL;
    }

    if (domain && username && password) {
        secIdent.User = (unsigned char *)username;
        secIdent.UserLength = MSVCRT$strlen(username);
        secIdent.Password = (unsigned char *)password;
        secIdent.PasswordLength = MSVCRT$strlen(password);
        secIdent.Domain = (unsigned char *)domain;
        secIdent.DomainLength = MSVCRT$strlen(domain);
        secIdent.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;
    }

    // LDAP bind
    // Check if we have valid creds
    if(!(domain && username && password))
    {
        // Use user of current process
        commonPrintf("Authenticating with process credentials\n");
        lRtn = WLDAP32$ldap_bind_s(ldapConnectionPtr, domainDN, NULL, LDAP_AUTH_NEGOTIATE);
    }
    else
    {
        // Use supplied creds
        commonPrintf("Authenticating with: %s\\%s:%s\n", domain, username, password);
        lRtn = WLDAP32$ldap_bind_s(ldapConnectionPtr, domainDN, (PCHAR)&secIdent, LDAP_AUTH_NEGOTIATE);
    }

    if (lRtn == LDAP_SUCCESS)
    {
        //commonPrintf("Bind successful\n");
    }
    else
    {
        commonPrintf("Bind failed: ERROR 0x%x\n", lRtn);
        WLDAP32$ldap_unbind(ldapConnectionPtr);
        return NULL;
    }

    return ldapConnectionPtr;
}

ULONG ldapExtSearch(LDAP* ldapConnectionPtr, CHAR* domainDN, CHAR* pFilter, PCHAR pAttributes[], ULONG numResults, ULONG controls)
{
    PLDAPSearch pageHandle = NULL;
    LDAPMessage *ldapMessage = NULL;
    ULONG totalEntries = 0;
    ULONG lRtn = 0;
    ULONG status = 0;
    ULONG numEntries = 0;
    ULONG pagecount = 0;
    LDAP_TIMEVAL timeout = {20, 0};
    LDAPControl **retCtrl = NULL;
    struct berval *pCookie = NULL;
    PCHAR cookie = NULL;

    // Create berval for SD Flags
    BerElement *pBerElmt = NULL;
    struct berval *pBerVal = NULL;

    pBerElmt = WLDAP32$ber_alloc_t(LBER_USE_DER);
    WLDAP32$ber_printf(pBerElmt, (PSTR)"{i}", (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION));
    WLDAP32$ber_flatten(pBerElmt, &pBerVal);
    WLDAP32$ber_free(pBerElmt, 1);

    // Create SD control manually
    // https://github.com/aurel26/gpocheck/blob/master/LDAP.cpp#L305-L313
    LDAPControl sdCtrl;
    sdCtrl.ldctl_iscritical = TRUE;
    sdCtrl.ldctl_oid = (PCHAR)LDAP_OID_SD_FLAGS;
    sdCtrl.ldctl_value.bv_val = pBerVal->bv_val;
    sdCtrl.ldctl_value.bv_len = pBerVal->bv_len;

    // Create a page control
    LDAPControl *pageCtrl = NULL;
    LDAPControl *ctrlArr[3] = {0};
    lRtn = WLDAP32$ldap_create_page_control(ldapConnectionPtr, 2, NULL, TRUE, &pageCtrl);
    if (lRtn != LDAP_SUCCESS)
    {
        commonPrintf("Failed to create page control\n");
        return 0;
    }
    
    switch(controls) {
        case 3:
            ctrlArr[0] = pageCtrl;
            ctrlArr[1] = &sdCtrl;
            ctrlArr[2] = NULL;
            break;
        case 2:
            ctrlArr[0] = pageCtrl;
            ctrlArr[1] = NULL;
            ctrlArr[2] = NULL;
            break;
        case 1:
            ctrlArr[0] = &sdCtrl;
            ctrlArr[1] = NULL;
            ctrlArr[2] = NULL;
            break;
    }

    // Initial search
    status = WLDAP32$ldap_search_ext_s(ldapConnectionPtr, domainDN, LDAP_SCOPE_SUBTREE, pFilter, pAttributes, 0, (controls >= 1 && controls <= 3) ? ctrlArr : NULL, NULL, &timeout, numResults, &ldapMessage);
    numEntries = ldapParse(ldapConnectionPtr, ldapMessage);
    totalEntries += numEntries;

    // Fetch Cookie value from last search
    lRtn = WLDAP32$ldap_parse_result(ldapConnectionPtr, ldapMessage, NULL, NULL, NULL, NULL, &retCtrl, FALSE);
    
    if(controls == 3 || controls == 2)
    {
        // Prepare page control from last result
        lRtn = WLDAP32$ldap_parse_page_control(ldapConnectionPtr, retCtrl, NULL, &pCookie);
        cookie = (PCHAR)(pCookie->bv_val);
        //commonPrintf("LDAP Cookie: %i\n", cookie);
        
        while((cookie != NULL || cookie != 0) && ldapMessage)
        {
            ULONG pageSize = (numResults && ((numResults - totalEntries) < 64)) ? numResults - totalEntries : 64;

            lRtn = WLDAP32$ldap_create_page_control(ldapConnectionPtr, pageSize, pCookie, TRUE, &pageCtrl);
            ctrlArr[0] = pageCtrl;

            status = WLDAP32$ldap_search_ext_s(ldapConnectionPtr, domainDN, LDAP_SCOPE_SUBTREE, pFilter, pAttributes, 0, ctrlArr, NULL, &timeout, numResults, &ldapMessage);
            numEntries = ldapParse(ldapConnectionPtr, ldapMessage);
            totalEntries += numEntries;
            
            // Fetch Cookie value from last search
            lRtn = WLDAP32$ldap_parse_result(ldapConnectionPtr, ldapMessage, NULL, NULL, NULL, NULL, &retCtrl, FALSE);
            
            // Prepare page control from last result
            lRtn = WLDAP32$ldap_parse_page_control(ldapConnectionPtr, retCtrl, NULL, &pCookie);
            cookie = (PCHAR)(pCookie->bv_val);
            //commonPrintf("LDAP Cookie: %i\n", cookie);
        }
    }

    if (pCookie)
    {
        WLDAP32$ber_bvfree(pCookie);
    }
    if (pBerVal)
    {
        WLDAP32$ber_bvfree(pBerVal);
    }
    if (retCtrl)
    {
        WLDAP32$ldap_controls_free(retCtrl);
    }
    if (pageCtrl)
    {
        WLDAP32$ldap_control_free(pageCtrl);
    }
    if (ldapMessage)
    {
        lRtn = WLDAP32$ldap_msgfree(ldapMessage);
        if (lRtn != LDAP_SUCCESS)
        {
            commonPrintf("Message free failed\n");
        }
    }
    if (pageHandle)
    {
        lRtn = WLDAP32$ldap_search_abandon_page(ldapConnectionPtr, pageHandle);
        if (lRtn != LDAP_SUCCESS)
        {
            commonPrintf("Abandon page failed\n");
        }
    }

    return totalEntries;
}

ULONG ldapPagedSearch(LDAP* ldapConnectionPtr, CHAR* domainDN, CHAR* pFilter, PCHAR pAttributes[], ULONG numResults)
{
    PLDAPSearch pageHandle = NULL;
    LDAPMessage *ldapMessage = NULL;
    ULONG lRtn = 0;
    ULONG status = 0;
    ULONG pagecount = 0;
    LDAP_TIMEVAL timeout = {20, 0};

    ULONG totalEntries = 0;

    pageHandle = WLDAP32$ldap_search_init_page(ldapConnectionPtr, domainDN, LDAP_SCOPE_SUBTREE, pFilter, pAttributes, 0, NULL, NULL, 15, numResults, NULL);
    if(pageHandle == NULL)
    {
        commonPrintf("Page handle failed\n");
        return totalEntries;
    }

    do {
        // search_init TotalSizeLimit will only limit results if the PageSzie in get_next_page is smaller, otherwise
        // pages of data an keep being requested until all search results are returned.
        // Therefore we need to keep track of the number of results.
        ULONG pageSize = (numResults && ((numResults - totalEntries) < 64)) ? numResults - totalEntries : 64;
        status = WLDAP32$ldap_get_next_page_s(ldapConnectionPtr, pageHandle, &timeout, pageSize, &pagecount, &ldapMessage);
        if (!ldapMessage || !(status == LDAP_SUCCESS || status == LDAP_NO_RESULTS_RETURNED))
        {
            break;
        }

        ULONG numEntries = ldapParse(ldapConnectionPtr, ldapMessage);
        totalEntries += numEntries;
    }
    while(status == LDAP_SUCCESS);
    
    if (ldapMessage)
    {
        lRtn = WLDAP32$ldap_msgfree(ldapMessage);
        if (lRtn != LDAP_SUCCESS)
        {
            commonPrintf("Message free failed\n");
        }
    }
    if (pageHandle)
    {
        lRtn = WLDAP32$ldap_search_abandon_page(ldapConnectionPtr, pageHandle);
        if (lRtn != LDAP_SUCCESS)
        {
            commonPrintf("Abandon page failed\n");
        }
    }

    return totalEntries;
}

ULONG ldapSyncSearch(LDAP* ldapConnectionPtr, ULONG scope, CHAR* domainDN, CHAR* pFilter, PCHAR pAttributes[], ULONG numResults)
{
    ULONG lRtn = 0;
    LDAPMessage *ldapMessage = NULL;

    // Limit number of results
    lRtn = WLDAP32$ldap_set_option(ldapConnectionPtr, LDAP_OPT_SIZELIMIT, (const void *) &numResults);
    if (lRtn == LDAP_SUCCESS)
    {
        commonPrintf("Results limited to %i results\n", numResults);
    }
    else
    {
        return 0;
    }

    // Non-Paged Search
    lRtn =
        WLDAP32$ldap_search_s(ldapConnectionPtr, domainDN, scope, "(objectClass=*)", pAttributes, 0, &ldapMessage);
    if (lRtn == LDAP_SUCCESS)
    {
        commonPrintf("Search successful\n");
    }
    else if (lRtn == LDAP_SIZELIMIT_EXCEEDED)
    {
        commonPrintf("Size limit reached, returning what we've received\n");
    }
    else
    {
        commonPrintf("Search FAILED: ERROR 0x%x\n", lRtn);
        return 0;
    }
    
    ULONG numEntries = ldapParse(ldapConnectionPtr, ldapMessage);
    
    if (ldapMessage)
    {
        lRtn = WLDAP32$ldap_msgfree(ldapMessage);
        if (lRtn != LDAP_SUCCESS)
        {
            commonPrintf("Message free failed\n");
        }
    }

    return numEntries;
}

// https://stuff.mit.edu/afs/athena/astaff/project/ldap/mozilla2k/sdkc3.1/docs/controls.htm
ULONG ldapSupportedControls(LDAP* ldapConnectionPtr)
{
    ULONG lRtn, i, sd_flag, paging = 0;
    LDAPMessage *ldapMessage = NULL;
    LDAPMessage *entry = NULL;
    PCHAR *pointersToValues = NULL;

    PCHAR attributes[2] = {0};
    attributes[0] = "supportedControl";
    attributes[1] = NULL;

    lRtn =
        WLDAP32$ldap_search_s(ldapConnectionPtr, "", LDAP_SCOPE_BASE, "(objectClass=*)", attributes, 0, &ldapMessage);
    if (lRtn != LDAP_SUCCESS)
    {
        commonPrintf("Root DSE search FAILED: ERROR 0x%x\n", lRtn);
        return 0;
    }

    entry = WLDAP32$ldap_first_entry(ldapConnectionPtr, ldapMessage);
    if (entry != NULL)
    {
        pointersToValues = WLDAP32$ldap_get_values(ldapConnectionPtr, entry, "supportedControl");
        if (pointersToValues != NULL)
        {
            for(i=0; pointersToValues[i] != NULL; i++)
            {
                if(MSVCRT$strcmp(pointersToValues[i], LDAP_OID_SD_FLAGS) == 0)
                {
                    sd_flag = 1;
                }
                if(MSVCRT$strcmp(pointersToValues[i], LDAP_OID_PAGED_RESULT) == 0)
                {
                    paging = 2;
                }
            }
        }
        if(pointersToValues != NULL)
        {
            WLDAP32$ldap_value_free(pointersToValues);
        }
    }
    else
    {
        commonPrintf("Couldn't fetch entry from Root DSE\n");
        return 0;
    }

    if (ldapMessage)
    {
        lRtn = WLDAP32$ldap_msgfree(ldapMessage);
        if (lRtn != LDAP_SUCCESS)
        {
            commonPrintf("Message free failed\n");
        }
    }

    return sd_flag + paging;
}

void ldapQuery(CHAR* pFilter, ULONG numResults, CHAR* attributes, CHAR* dc, CHAR* basename, CHAR* domain, CHAR* username, CHAR* password)
{
    commonPrintf("Filter: %s\n", pFilter);

    PCHAR pAttributes[MAX_ATTRIBUTES] = {0};
    
    if(attributes) {
        commonPrintf("Attributes: %s\n", attributes);
        //https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/strtok-strtok-l-wcstok-wcstok-l-mbstok-mbstok-l?view=msvc-170#example
        int attributeCount = 0;
        char *token = NULL;
        const char delimiter[2] = ",";

        token = MSVCRT$strtok(attributes, delimiter);
        while(token != NULL)
        {
            if(attributeCount < (MAX_ATTRIBUTES - 1))
            {
                pAttributes[attributeCount] = token;
                attributeCount++;
                token = MSVCRT$strtok(NULL, delimiter);
            }
            else
            {
                commonPrintf("Attributes capped at %i, remainder will be ommited\n", MAX_ATTRIBUTES-1);
                break;
            }
        }
    }
    else
    {
        commonPrintf("Returning all attributes\n");
    }

    commonPrintf("Results limit: %i\n", numResults);

    // TODO: Local variables are stored on the stack, consider allocating heap
    // Domain DN Name
    char userId[USERNAME_BUFFER] = {0};
    ULONG userIdLength = 0;
    char *domainDN = NULL;

    // Certain variables must be defined BEFORE any call to "goto end;"
    // otherwise the code will start to check undefined variables
    // Primary Domain Controller
    PDOMAIN_CONTROLLER_INFO pdcInfo = NULL;
    char *pdc = NULL;

    // LDAP session handle
    LDAP *ldapConnectionPtr = NULL;

    // Retrieve the FQDN associated with the calling thread
    // https://docs.microsoft.com/en-us/windows/win32/api/secext/nf-secext-getusernameexa
    userIdLength = sizeof(userId);
    BOOLEAN result = SECUR32$GetUserNameExA(NameFullyQualifiedDN, userId, &userIdLength);

    // Get Domain distinguished name if previous call was successfull
    if (result != 0)
    {
        commonPrintf("User: %s\n", userId);

        domainDN = (basename) ? basename : MSVCRT$strstr(userId, "DC");

        if (domainDN != NULL)
        {
            commonPrintf("Base: %s\n", domainDN);
        }
        else
        {
            commonPrintf("MSVCRT strstr: Failed to fetch Domain DN\n");
        }
    }
    else
    {
        commonPrintf("SECUR32 GetUserNameExA: Error fetching user FQDN\n");

        // https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
        DWORD error = KERNEL32$GetLastError();

        // https://docs.microsoft.com/en-gb/windows/win32/debug/system-error-codes--0-499-
        switch (error)
        {
        case ERROR_MORE_DATA:
            commonPrintf("Username buffer is too small, adjust and re-compile\n");
            break;
        case ERROR_NO_SUCH_DOMAIN:
            commonPrintf("DC not available\n");
            break;
        case ERROR_NONE_MAPPED:
            commonPrintf("DN format not available\n");
        }

        goto end;
    }

    // Get Primary Domain Controller (PDC)
    // https://docs.microsoft.com/en-us/windows/win32/api/dsgetdc/nf-dsgetdc-dsgetdcnamea
    DWORD getPDC = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &pdcInfo);

    // + 2 removes the \\ from the front of the name
    if (ERROR_SUCCESS == getPDC)
    {
        pdc = (dc) ? dc : pdcInfo->DomainControllerName + 2;
        commonPrintf("Server: %s\n", pdc);
    }
    else
    {
        goto end;
    }

    ULONG totalEntries = 0;

    ldapConnectionPtr = ldapConnect(LDAP_VERSION3, pdc, domainDN, domain, username, password);
    if(ldapConnectionPtr != NULL)
    {
        ULONG controls = ldapSupportedControls(ldapConnectionPtr);
        ldapWhoami(ldapConnectionPtr);
        //commonPrintf("Controls: %i\n", controls);

        switch(controls)
        {
            case 0:
                commonPrintf("Fallback to sync search\n");
                break;
            case 3:
                commonPrintf("Ext search with paging\n");
                totalEntries = ldapExtSearch(ldapConnectionPtr, domainDN, pFilter, pAttributes, numResults, controls);
                break;
            case 2:
                commonPrintf("Paged only search\n");
                // Technically we can but ldapExtSearch here as well, but I coded it so we're going to use it
                totalEntries = ldapPagedSearch(ldapConnectionPtr, domainDN, pFilter, pAttributes, numResults);
                break;
            case 1:
                commonPrintf("Ext search non-paged\n");
                totalEntries = ldapExtSearch(ldapConnectionPtr, domainDN, pFilter, pAttributes, numResults, controls);
        }
        commonPrintf("-----------------\n");
        commonPrintf("Total: %i\n", totalEntries);
    }
    else
    {
        if (ldapConnectionPtr)
        {
            WLDAP32$ldap_unbind(ldapConnectionPtr);
        }

        ldapConnectionPtr = ldapConnect(LDAP_VERSION2, pdc, domainDN, domain, username, password);

        if (ldapConnectionPtr != NULL)
        {
            totalEntries = ldapSyncSearch(ldapConnectionPtr, LDAP_SCOPE_BASE, domainDN, pFilter, pAttributes, numResults);
        }
    }

end:
    // Free structure used to retrive PDC
    if (pdcInfo)
    {
        NETAPI32$NetApiBufferFree(pdcInfo);
        pdcInfo = NULL;
    }
    // Free LDAP session handle
    if (ldapConnectionPtr)
    {
        ULONG lRtn = WLDAP32$ldap_unbind(ldapConnectionPtr);
        if (lRtn == LDAP_SUCCESS)
        {
            //commonPrintf("Connection closed\n");
        }
        else
        {
            commonPrintf("Unbind failed\n");
        }
    }
}

// Main Functions
#ifdef BOF

void go(char *args, int alen)
{
    // Create page to use for output
    currentPageSize = 0;
    page = (char *)MSVCRT$calloc(totalPageSize, sizeof(char));

    datap parser;
    CHAR* filter;
    ULONG numResults;
    CHAR* attributes;
    CHAR* dc;
    CHAR* basename;
    CHAR* domain;
    CHAR* username;
    CHAR* password;

    BeaconDataParse(&parser, args, alen);
    filter = BeaconDataExtract(&parser, NULL);
    numResults = BeaconDataInt(&parser);
    attributes = BeaconDataExtract(&parser, NULL);
    dc = BeaconDataExtract(&parser, NULL);
    basename = BeaconDataExtract(&parser, NULL);
    domain = BeaconDataExtract(&parser, NULL);
    username = BeaconDataExtract(&parser, NULL);
    password = BeaconDataExtract(&parser, NULL);

    // Set values to null if strings are empty
    attributes = *attributes == 0 ? NULL : attributes;
    dc = *dc == 0 ? NULL : dc;
    basename = *basename == 0 ? NULL : basename;
    domain = *domain == 0 ? NULL : domain;
    username = *username == 0 ? NULL : username;
    password = *password == 0 ? NULL : password;

    // Execute LDAP query
    ldapQuery(filter, numResults, attributes, dc, basename, domain, username, password);

    // Print output page
    print_page(TRUE);
}

#else

int main(int argc, char *argv[])
{
    char attributes[] = "samAccountName,ntSecurityDescriptor";
    char dc[] = "";
    char basename[] = "";
    char domain[] = "test";
    char username[] = "test";
    char password[] = "pass";

    // The next two examples won't work when we use strtok against the attributes
    // This is because strtok modifies the attributes variable
    // attributes will be read only memory in both these instances
    // char *attr = "samAccountName,objectClass";
    // ldapQuery("(objectClass=user)", 2, "samAccountName,objectClass")

    ldapQuery("(samAccountName=test)", 5, attributes, NULL, NULL, domain, username, password);
    return 1;
}

#endif
