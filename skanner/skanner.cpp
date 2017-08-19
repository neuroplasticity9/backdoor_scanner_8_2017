#include "stdafx.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <Shlobj.h>
#include <Shlwapi.h>
#include <conio.h>
#include <stdio.h>
#include <lmcons.h>

#pragma comment(lib, "Shlwapi.lib")
const char *files[] = {"rastls.dll", "OUTLFLTR.DAT" };

BOOL ScanProcesses();
BOOL ScanProcessModules(DWORD pid);
BOOL ScanFiles();
BOOL CheckFileExists(char *path);
BOOL IsCurrentUserLocalAdministrator(void);
void EnableDebugPriv();


int main()
{
	if (!IsCurrentUserLocalAdministrator())
	{
		printf("Vui long chay chuong trinh voi quyen Admin\nRight click -> Run as Administrator\n");
		_getch();
		return 1;
	}
	__try
	{
		if (ScanProcesses() || ScanFiles())
		{
			printf("Phat hien ma doc tren may tinh cua ban!\nVui long lien he bo phan Helpdesk de duoc ho tro.\n");
		} else printf("Khong phat hien ma doc!\n");
		_getch();
		return 0;
	}
	__finally
	{
		printf("Xay ra loi, vui long chay lai chuong trinh!");
	}
}

BOOL ScanFiles()
{
	char programfile_path[MAX_PATH];
	char appdata_path[MAX_PATH];
	char programfilex86_path[MAX_PATH];

	if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES, NULL, 0, programfile_path)))
	{
		if (CheckFileExists(programfile_path)) return(TRUE);
	}
	if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, programfilex86_path)))
	{
		if (CheckFileExists(programfilex86_path)) return(TRUE);
	}
	if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, appdata_path)))
	{
		if (CheckFileExists(appdata_path)) return(TRUE);
	}
	return(FALSE);
}

BOOL CheckFileExists(char * path)
{
	for (int i = 0; i < (sizeof(files)/sizeof(*files)); i++)
	{
		char pszPath[MAX_PATH];
		ZeroMemory(pszPath, MAX_PATH);
		strcpy(pszPath, (const char*)path);
		PathAppendA(pszPath, "Symantec\\MSOfficetasks");
		PathAppendA(pszPath, files[i]);
		if (PathFileExists(pszPath)){
			return(TRUE);
		}
	}
	return(FALSE);
}

BOOL ScanProcesses()
{
	EnableDebugPriv();
	HANDLE hProcessSnapshot;
	PROCESSENTRY32 pe32;

	hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE) {
		return(FALSE);
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnapshot, &pe32)) {
		CloseHandle(hProcessSnapshot);
		return(FALSE);
	}
	do
	{
		if (ScanProcessModules(pe32.th32ProcessID))
		{
			CloseHandle(hProcessSnapshot);
			return(TRUE);
		}
	} while (Process32Next(hProcessSnapshot, &pe32));
	CloseHandle(hProcessSnapshot);
	return(FALSE);
}

BOOL ScanProcessModules(DWORD dwPID)
{
	//printf("Processing PID %d\n", (int)dwPID);
	HANDLE hModuleSnapShot = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	char modulePath[MAX_PATH];

	hModuleSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID);
	if (hModuleSnapShot == INVALID_HANDLE_VALUE)
	{
		//DWORD last_error = GetLastError();
		return(FALSE);
	}
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnapShot, &me32))
	{
		CloseHandle(hModuleSnapShot);
		return(FALSE);
	}
	
	if (FAILED(SHGetFolderPath(NULL, CSIDL_SYSTEM, NULL, 0, modulePath)))
	{
		CloseHandle(hModuleSnapShot);
		return(FALSE);
	}
	PathAppend(modulePath, "rastls.dll");
	do
	{
		if (!_stricmp(me32.szModule, "rastls.dll"))
		{
			if (_stricmp(me32.szExePath, modulePath))
			{
				CloseHandle(hModuleSnapShot);
				return(TRUE);
			}
		}
	} while (Module32Next(hModuleSnapShot, &me32));
	CloseHandle(hModuleSnapShot);
	return(FALSE);
}

void EnableDebugPriv()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;

	ZeroMemory(&tkp, sizeof(tkp));
	if(!OpenProcessToken(GetCurrentProcess(), (TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY), &hToken))
		return;
    if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return;
    }
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL);
	CloseHandle(hToken);
	return;
}

BOOL IsCurrentUserLocalAdministrator(void)
{
   BOOL   fReturn         = FALSE;
   DWORD  dwStatus;
   DWORD  dwAccessMask;
   DWORD  dwAccessDesired;
   DWORD  dwACLSize;
   DWORD  dwStructureSize = sizeof(PRIVILEGE_SET);
   PACL   pACL            = NULL;
   PSID   psidAdmin       = NULL;

   HANDLE hToken              = NULL;
   HANDLE hImpersonationToken = NULL;

   PRIVILEGE_SET   ps;
   GENERIC_MAPPING GenericMapping;

   PSECURITY_DESCRIPTOR     psdAdmin           = NULL;
   SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;
	/*
      Determine if the current thread is running as a user that is a member of the local admins group.
	  To do this, create a security descriptor that has a DACL which has an ACE that allows only local aministrators access.
      Then, call AccessCheck with the current thread's token and the security descriptor.
	  It will say whether the user could access an object if it had that security descriptor.
	  Note: you do not need to actually create the object.  Just checking access against the security descriptor alone will be sufficient.
   */
   const DWORD ACCESS_READ  = 1;
   const DWORD ACCESS_WRITE = 2;
   __try
   {
      /*
         AccessCheck() requires an impersonation token.  We first get a primary token and then create a duplicate impersonation token.
		 The impersonation token is not actually assigned to the thread, but is used in the call to AccessCheck.
		 Thus, this function itself never impersonates, but does use the identity of the thread.
		 If the thread was impersonating already, this function uses that impersonation context.
      */
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE|TOKEN_QUERY, TRUE, &hToken))
	{
		if (GetLastError() != ERROR_NO_TOKEN)
			__leave;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE|TOKEN_QUERY, &hToken))
		__leave;
	}
    if (!DuplicateToken (hToken, SecurityImpersonation, &hImpersonationToken))
        __leave;
      /*
        Create the binary representation of the well-known SID that represents the local administrators group.
		Then create the security descriptor and DACL with an ACE that allows only local admins access.
        After that, perform the access check.  This will determine whether the current user is a local admin.
      */
    if (!AllocateAndInitializeSid(&SystemSidAuthority, 2, 
		SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 
		0, 0, 0, 0, 0, 0, &psidAdmin))
		__leave;

    psdAdmin = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
    if (psdAdmin == NULL)
		__leave;

    if (!InitializeSecurityDescriptor(psdAdmin, SECURITY_DESCRIPTOR_REVISION))
		__leave;

      // Compute size needed for the ACL.
    dwACLSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psidAdmin) - sizeof(DWORD);

    pACL = (PACL)LocalAlloc(LPTR, dwACLSize);
    if (pACL == NULL)
        __leave;
    if (!InitializeAcl(pACL, dwACLSize, ACL_REVISION2))
        __leave;
    dwAccessMask= ACCESS_READ | ACCESS_WRITE;
    if (!AddAccessAllowedAce(pACL, ACL_REVISION2, dwAccessMask, psidAdmin))
		__leave;
    if (!SetSecurityDescriptorDacl(psdAdmin, TRUE, pACL, FALSE))
        __leave;
	/*
         AccessCheck validates a security descriptor somewhat; set the group and owner so that enough of the security descriptor is filled out to make AccessCheck happy.
      */
    SetSecurityDescriptorGroup(psdAdmin, psidAdmin, FALSE);
    SetSecurityDescriptorOwner(psdAdmin, psidAdmin, FALSE);
    if (!IsValidSecurityDescriptor(psdAdmin))
        __leave;
    dwAccessDesired = ACCESS_READ;
    //	Initialize GenericMapping structure even though you do not use generic rights.
    GenericMapping.GenericRead    = ACCESS_READ;
    GenericMapping.GenericWrite   = ACCESS_WRITE;
    GenericMapping.GenericExecute = 0;
    GenericMapping.GenericAll     = ACCESS_READ | ACCESS_WRITE;

    if (!AccessCheck(psdAdmin, hImpersonationToken, dwAccessDesired,
                    &GenericMapping, &ps, &dwStructureSize, &dwStatus,
                    &fReturn))
    {
        fReturn = FALSE;
        __leave;
    }
}
	__finally
	{
	// Clean up.
		if (pACL) LocalFree(pACL);
		if (psdAdmin) LocalFree(psdAdmin);
		if (psidAdmin) FreeSid(psidAdmin);
		if (hImpersonationToken) CloseHandle (hImpersonationToken);
		if (hToken) CloseHandle (hToken);
	}
	return fReturn;
}
