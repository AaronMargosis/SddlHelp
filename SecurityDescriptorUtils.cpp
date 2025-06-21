#include <Windows.h>
#include <winevt.h>
#include <Iads.h>
#include <NtDsAPI.h>
#include <LM.h> // to get max domain and username lengths
#include <sddl.h>
#include <iostream>
#include <sstream>
#include "SysErrorMessage.h"
#include "HEX.h"
#include "SecurityDescriptorUtils.h"
#include "CSid.h"
#include "StringUtils.h"

//TODO: Could add more object types: synch objects, job objects
// https://docs.microsoft.com/en-us/windows/win32/sync/synchronization-object-security-and-access-rights
// https://docs.microsoft.com/en-us/windows/win32/procthread/job-object-security-and-access-rights

// --------------------------------------------------------------------------------
// Common utility function(s)

/// <summary>
/// Returns true if the bit(s) in dwBits are all set in dwValue
/// </summary>
static inline bool BitPresent(DWORD dwBits, DWORD dwValue)
{
	return (dwBits == (dwBits & dwValue));
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// ACE types

/// <summary>
/// For mapping ACE type to corresponding name
/// </summary>
struct ace_t { DWORD aceType; const wchar_t* szName; };

static ace_t aceTypes[] = {
	{ ACCESS_ALLOWED_ACE_TYPE, L"ACCESS_ALLOWED_ACE_TYPE" },
	{ ACCESS_DENIED_ACE_TYPE, L"ACCESS_DENIED_ACE_TYPE" },
	{ SYSTEM_AUDIT_ACE_TYPE, L"SYSTEM_AUDIT_ACE_TYPE" },
	{ SYSTEM_ALARM_ACE_TYPE, L"SYSTEM_ALARM_ACE_TYPE" },
	{ ACCESS_ALLOWED_COMPOUND_ACE_TYPE, L"ACCESS_ALLOWED_COMPOUND_ACE_TYPE" },
	{ ACCESS_ALLOWED_OBJECT_ACE_TYPE, L"ACCESS_ALLOWED_OBJECT_ACE_TYPE" },
	{ ACCESS_DENIED_OBJECT_ACE_TYPE, L"ACCESS_DENIED_OBJECT_ACE_TYPE" },
	{ SYSTEM_AUDIT_OBJECT_ACE_TYPE, L"SYSTEM_AUDIT_OBJECT_ACE_TYPE" },
	{ SYSTEM_ALARM_OBJECT_ACE_TYPE, L"SYSTEM_ALARM_OBJECT_ACE_TYPE" },
	{ ACCESS_ALLOWED_CALLBACK_ACE_TYPE, L"ACCESS_ALLOWED_CALLBACK_ACE_TYPE" },
	{ ACCESS_DENIED_CALLBACK_ACE_TYPE, L"ACCESS_DENIED_CALLBACK_ACE_TYPE" },
	{ ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, L"ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE" },
	{ ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, L"ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE" },
	{ SYSTEM_AUDIT_CALLBACK_ACE_TYPE, L"SYSTEM_AUDIT_CALLBACK_ACE_TYPE" },
	{ SYSTEM_ALARM_CALLBACK_ACE_TYPE, L"SYSTEM_ALARM_CALLBACK_ACE_TYPE" },
	{ SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, L"SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE" },
	{ SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE, L"SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE" },
	{ SYSTEM_MANDATORY_LABEL_ACE_TYPE, L"SYSTEM_MANDATORY_LABEL_ACE_TYPE" },
	{ 0, nullptr } };

/// <summary>
/// Returns text corresponding to a valid ACE type value.
/// </summary>
/// <param name="dwAceType">Input: ACE type</param>
/// <returns>String value corresponding to the ACE type; nullptr if ACE type value not recognized.</returns>
static const wchar_t* AceType(DWORD dwAceType)
{
	for (ace_t* pAce = aceTypes; pAce->szName != nullptr; pAce++)
	{
		if (dwAceType == pAce->aceType)
		{
			return pAce->szName;
		}
	}
	return nullptr;
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
struct flags_t { DWORD flag; const wchar_t* szName; };

static flags_t controlFlags[] = {
	{ SE_OWNER_DEFAULTED, L"SE_OWNER_DEFAULTED" },
	{ SE_GROUP_DEFAULTED, L"SE_GROUP_DEFAULTED" },
	{ SE_DACL_PRESENT, L"SE_DACL_PRESENT" },
	{ SE_DACL_DEFAULTED, L"SE_DACL_DEFAULTED" },
	{ SE_SACL_PRESENT, L"SE_SACL_PRESENT" },
	{ SE_SACL_DEFAULTED, L"SE_SACL_DEFAULTED" },
	{ SE_DACL_AUTO_INHERIT_REQ, L"SE_DACL_AUTO_INHERIT_REQ" },
	{ SE_SACL_AUTO_INHERIT_REQ, L"SE_SACL_AUTO_INHERIT_REQ" },
	{ SE_DACL_AUTO_INHERITED, L"SE_DACL_AUTO_INHERITED" },
	{ SE_SACL_AUTO_INHERITED, L"SE_SACL_AUTO_INHERITED" },
	{ SE_DACL_PROTECTED, L"SE_DACL_PROTECTED" },
	{ SE_SACL_PROTECTED, L"SE_SACL_PROTECTED" },
	{ SE_RM_CONTROL_VALID, L"SE_RM_CONTROL_VALID" },
	{ SE_SELF_RELATIVE, L"SE_SELF_RELATIVE" },
	{ 0, nullptr } };

static flags_t aceFlags[] = {
	{CONTAINER_INHERIT_ACE,      L"CONTAINER_INHERIT_ACE"},
	{FAILED_ACCESS_ACE_FLAG,     L"FAILED_ACCESS_ACE_FLAG"},
	{INHERIT_ONLY_ACE,           L"INHERIT_ONLY_ACE"},
	{INHERITED_ACE,              L"INHERITED_ACE"},
	{NO_PROPAGATE_INHERIT_ACE,   L"NO_PROPAGATE_INHERIT_ACE"},
	{OBJECT_INHERIT_ACE,         L"OBJECT_INHERIT_ACE"},
	{SUCCESSFUL_ACCESS_ACE_FLAG, L"SUCCESSFUL_ACCESS_ACE_FLAG"},
	{ 0, nullptr } };

static void OutputFlagsOnOneLine(std::wostream& sOut, const flags_t* pFlags, DWORD dwFlags)
{
	for ( ; pFlags->szName != nullptr; pFlags++)
	{
		if (BitPresent(pFlags->flag, dwFlags))
			sOut << pFlags->szName << L" ";
	}
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
/// <summary>
/// Generic and object-specific permission values.
/// The xSpecific arrays are object-specific bitmasks.
/// The xMask arrays are standard/generic bitmasks.
/// The xMatch arrays are aggregated sets of permissions.
/// </summary>
struct perm_t { DWORD mask; const wchar_t * szName; };

// --------------------------------------------------------------------------------
static perm_t standardMask[] = {
	{ DELETE, L"DELETE" },
	{ READ_CONTROL, L"READ_CONTROL" },
	{ WRITE_DAC, L"WRITE_DAC" },
	{ WRITE_OWNER, L"WRITE_OWNER" },
	{ SYNCHRONIZE, L"SYNCHRONIZE" },
	{ ACCESS_SYSTEM_SECURITY, L"ACCESS_SYSTEM_SECURITY" },
	{ MAXIMUM_ALLOWED, L"MAXIMUM_ALLOWED" },
	{ 0, nullptr } };

static perm_t genericMask[] = {
	{ GENERIC_READ, L"GENERIC_READ" },
	{ GENERIC_WRITE, L"GENERIC_WRITE" },
	{ GENERIC_EXECUTE, L"GENERIC_EXECUTE" },
	{ GENERIC_ALL, L"GENERIC_ALL" },
	{ 0, nullptr } };

static perm_t standardAndGenericMask[] = {
	{ DELETE, L"DELETE" },
	{ READ_CONTROL, L"READ_CONTROL" },
	{ WRITE_DAC, L"WRITE_DAC" },
	{ WRITE_OWNER, L"WRITE_OWNER" },
	{ SYNCHRONIZE, L"SYNCHRONIZE" },
	{ STANDARD_RIGHTS_REQUIRED, L"STANDARD_RIGHTS_REQUIRED" },
	//{ STANDARD_RIGHTS_ALL, L"STANDARD_RIGHTS_ALL" },
	//{ SPECIFIC_RIGHTS_ALL, L"SPECIFIC_RIGHTS_ALL" },
	{ ACCESS_SYSTEM_SECURITY, L"ACCESS_SYSTEM_SECURITY" },
	{ MAXIMUM_ALLOWED, L"MAXIMUM_ALLOWED" },
	{ GENERIC_READ, L"GENERIC_READ" },
	{ GENERIC_WRITE, L"GENERIC_WRITE" },
	{ GENERIC_EXECUTE, L"GENERIC_EXECUTE" },
	{ GENERIC_ALL, L"GENERIC_ALL" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------
static perm_t fileSpecific[] = {
	{ FILE_READ_DATA, L"FILE_READ_DATA" },
	{ FILE_WRITE_DATA, L"FILE_WRITE_DATA" },
	{ FILE_APPEND_DATA, L"FILE_APPEND_DATA" },
	{ FILE_READ_EA, L"FILE_READ_EA" },
	{ FILE_WRITE_EA, L"FILE_WRITE_EA" },
	{ FILE_EXECUTE, L"FILE_EXECUTE" },
	{ FILE_READ_ATTRIBUTES, L"FILE_READ_ATTRIBUTES" },
	{ FILE_WRITE_ATTRIBUTES, L"FILE_WRITE_ATTRIBUTES" },
	{ 0, nullptr } };

static perm_t dirSpecific[] = {
	{ FILE_LIST_DIRECTORY, L"FILE_LIST_DIRECTORY" },
	{ FILE_ADD_FILE, L"FILE_ADD_FILE" },
	{ FILE_ADD_SUBDIRECTORY, L"FILE_ADD_SUBDIRECTORY" },
	{ FILE_READ_EA, L"FILE_READ_EA" },
	{ FILE_WRITE_EA, L"FILE_WRITE_EA" },
	{ FILE_TRAVERSE, L"FILE_TRAVERSE" },
	{ FILE_DELETE_CHILD, L"FILE_DELETE_CHILD" },
	{ FILE_READ_ATTRIBUTES, L"FILE_READ_ATTRIBUTES" },
	{ FILE_WRITE_ATTRIBUTES, L"FILE_WRITE_ATTRIBUTES" },
	{ 0, nullptr } };

static perm_t pipeSpecific[] = {
	{ FILE_READ_DATA, L"FILE_READ_DATA" },
	{ FILE_WRITE_DATA, L"FILE_WRITE_DATA" },
	{ FILE_CREATE_PIPE_INSTANCE, L"FILE_CREATE_PIPE_INSTANCE" },
	{ FILE_READ_ATTRIBUTES, L"FILE_READ_ATTRIBUTES" },
	{ FILE_WRITE_ATTRIBUTES, L"FILE_WRITE_ATTRIBUTES" },
	{ 0, nullptr } };

static perm_t fileMatch[] = {
	{ FILE_ALL_ACCESS, L"FILE_ALL_ACCESS" },
	{ FILE_GENERIC_READ, L"FILE_GENERIC_READ" },
	{ FILE_GENERIC_WRITE, L"FILE_GENERIC_WRITE" },
	{ FILE_GENERIC_EXECUTE, L"FILE_GENERIC_EXECUTE" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------
static perm_t keySpecific[] = {
	{ KEY_QUERY_VALUE, L"KEY_QUERY_VALUE" },
	{ KEY_SET_VALUE, L"KEY_SET_VALUE" },
	{ KEY_CREATE_SUB_KEY, L"KEY_CREATE_SUB_KEY" },
	{ KEY_ENUMERATE_SUB_KEYS, L"KEY_ENUMERATE_SUB_KEYS" },
	{ KEY_NOTIFY, L"KEY_NOTIFY" },
	{ KEY_CREATE_LINK, L"KEY_CREATE_LINK" },
	{ KEY_WOW64_32KEY, L"KEY_WOW64_32KEY" },
	{ KEY_WOW64_64KEY, L"KEY_WOW64_64KEY" },
	{ 0, nullptr } };

static perm_t keyMatch[] = {
	{ KEY_READ, L"KEY_READ" },
	{ KEY_WRITE, L"KEY_WRITE" },
	{ KEY_EXECUTE, L"KEY_EXECUTE" },
	{ KEY_ALL_ACCESS, L"KEY_ALL_ACCESS" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------
static perm_t serviceSpecific[] = {
	{ SERVICE_QUERY_CONFIG, L"SERVICE_QUERY_CONFIG" },
	{ SERVICE_CHANGE_CONFIG, L"SERVICE_CHANGE_CONFIG" },
	{ SERVICE_QUERY_STATUS, L"SERVICE_QUERY_STATUS" },
	{ SERVICE_ENUMERATE_DEPENDENTS, L"SERVICE_ENUMERATE_DEPENDENTS" },
	{ SERVICE_START, L"SERVICE_START" },
	{ SERVICE_STOP, L"SERVICE_STOP" },
	{ SERVICE_PAUSE_CONTINUE, L"SERVICE_PAUSE_CONTINUE" },
	{ SERVICE_INTERROGATE, L"SERVICE_INTERROGATE" },
	{ SERVICE_USER_DEFINED_CONTROL, L"SERVICE_USER_DEFINED_CONTROL" },
	{ 0, nullptr } };

static perm_t serviceMatch[] = {
	{ SERVICE_ALL_ACCESS, L"SERVICE_ALL_ACCESS" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------
static perm_t scmSpecific[] = {
	{ SC_MANAGER_CONNECT, L"SC_MANAGER_CONNECT" },
	{ SC_MANAGER_CREATE_SERVICE, L"SC_MANAGER_CREATE_SERVICE" },
	{ SC_MANAGER_ENUMERATE_SERVICE, L"SC_MANAGER_ENUMERATE_SERVICE" },
	{ SC_MANAGER_LOCK, L"SC_MANAGER_LOCK" },
	{ SC_MANAGER_QUERY_LOCK_STATUS, L"SC_MANAGER_QUERY_LOCK_STATUS" },
	{ SC_MANAGER_MODIFY_BOOT_CONFIG, L"SC_MANAGER_MODIFY_BOOT_CONFIG" },
	{ 0, nullptr } };

static perm_t scmMatch[] = {
	{ SC_MANAGER_ALL_ACCESS, L"SC_MANAGER_ALL_ACCESS" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------
static perm_t processSpecific[] = {
	{ PROCESS_TERMINATE, L"PROCESS_TERMINATE" },
	{ PROCESS_CREATE_THREAD, L"PROCESS_CREATE_THREAD" },
	{ PROCESS_SET_SESSIONID, L"PROCESS_SET_SESSIONID" },
	{ PROCESS_VM_OPERATION, L"PROCESS_VM_OPERATION" },
	{ PROCESS_VM_READ, L"PROCESS_VM_READ" },
	{ PROCESS_VM_WRITE, L"PROCESS_VM_WRITE" },
	{ PROCESS_DUP_HANDLE, L"PROCESS_DUP_HANDLE" },
	{ PROCESS_CREATE_PROCESS, L"PROCESS_CREATE_PROCESS" },
	{ PROCESS_SET_QUOTA, L"PROCESS_SET_QUOTA" },
	{ PROCESS_SET_INFORMATION, L"PROCESS_SET_INFORMATION" },
	{ PROCESS_QUERY_INFORMATION, L"PROCESS_QUERY_INFORMATION" },
	{ PROCESS_SUSPEND_RESUME, L"PROCESS_SUSPEND_RESUME" },
	{ PROCESS_QUERY_LIMITED_INFORMATION, L"PROCESS_QUERY_LIMITED_INFORMATION" },
	{ PROCESS_SET_LIMITED_INFORMATION, L"PROCESS_SET_LIMITED_INFORMATION" },
	{ 0, nullptr } };

static perm_t processMatch[] = {
	{ PROCESS_ALL_ACCESS, L"PROCESS_ALL_ACCESS" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------
static perm_t threadSpecific[] = {
	{ THREAD_TERMINATE, L"THREAD_TERMINATE" },
	{ THREAD_SUSPEND_RESUME, L"THREAD_SUSPEND_RESUME" },
	{ THREAD_GET_CONTEXT, L"THREAD_GET_CONTEXT" },
	{ THREAD_SET_CONTEXT, L"THREAD_SET_CONTEXT" },
	{ THREAD_QUERY_INFORMATION, L"THREAD_QUERY_INFORMATION" },
	{ THREAD_SET_INFORMATION, L"THREAD_SET_INFORMATION" },
	{ THREAD_SET_THREAD_TOKEN, L"THREAD_SET_THREAD_TOKEN" },
	{ THREAD_IMPERSONATE, L"THREAD_IMPERSONATE" },
	{ THREAD_DIRECT_IMPERSONATION, L"THREAD_DIRECT_IMPERSONATION" },
	{ THREAD_SET_LIMITED_INFORMATION, L"THREAD_SET_LIMITED_INFORMATION" },
	{ THREAD_QUERY_LIMITED_INFORMATION, L"THREAD_QUERY_LIMITED_INFORMATION" },
	{ THREAD_RESUME, L"THREAD_RESUME" },
	{ 0, nullptr } };

static perm_t threadMatch[] = {
	{ THREAD_ALL_ACCESS, L"THREAD_ALL_ACCESS" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------
#define SRVSVC_SHARE_CONNECT           0x0001  
#define SRVSVC_PAUSED_SHARE_CONNECT    0x0002  
#define SRVSVC_SHARE_CONNECT_ALL_ACCESS ( STANDARD_RIGHTS_REQUIRED | SRVSVC_SHARE_CONNECT | SRVSVC_PAUSED_SHARE_CONNECT)

static perm_t shareSpecific[] = {
	{ SRVSVC_SHARE_CONNECT, L"SRVSVC_SHARE_CONNECT" },
	{ SRVSVC_PAUSED_SHARE_CONNECT, L"SRVSVC_PAUSED_SHARE_CONNECT" },
	{ 0, nullptr } };

static perm_t shareMatch[] = {
	{ SRVSVC_SHARE_CONNECT_ALL_ACCESS, L"SRVSVC_SHARE_CONNECT_ALL_ACCESS" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------

static perm_t ComSpecific[] = {
	{ COM_RIGHTS_EXECUTE, L"COM_RIGHTS_EXECUTE" },
	{ COM_RIGHTS_EXECUTE_LOCAL, L"COM_RIGHTS_EXECUTE_LOCAL" },
	{ COM_RIGHTS_EXECUTE_REMOTE, L"COM_RIGHTS_EXECUTE_REMOTE" },
	{ COM_RIGHTS_ACTIVATE_LOCAL, L"COM_RIGHTS_ACTIVATE_LOCAL" },
	{ COM_RIGHTS_ACTIVATE_REMOTE, L"COM_RIGHTS_ACTIVATE_REMOTE" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------
static perm_t winstaSpecific[] = {
	{ WINSTA_ENUMDESKTOPS, L"WINSTA_ENUMDESKTOPS" },
	{ WINSTA_READATTRIBUTES, L"WINSTA_READATTRIBUTES" },
	{ WINSTA_ACCESSCLIPBOARD, L"WINSTA_ACCESSCLIPBOARD" },
	{ WINSTA_CREATEDESKTOP, L"WINSTA_CREATEDESKTOP" },
	{ WINSTA_WRITEATTRIBUTES, L"WINSTA_WRITEATTRIBUTES" },
	{ WINSTA_ACCESSGLOBALATOMS, L"WINSTA_ACCESSGLOBALATOMS" },
	{ WINSTA_EXITWINDOWS, L"WINSTA_EXITWINDOWS" },
	{ WINSTA_ENUMERATE, L"WINSTA_ENUMERATE" },
	{ WINSTA_READSCREEN, L"WINSTA_READSCREEN" },
	{ 0, nullptr } };

static perm_t winstaMatch[] = {
	{ WINSTA_ALL_ACCESS, L"WINSTA_ALL_ACCESS" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------
static perm_t desktopSpecific[] = {
	{ DESKTOP_READOBJECTS, L"DESKTOP_READOBJECTS" },
	{ DESKTOP_CREATEWINDOW, L"DESKTOP_CREATEWINDOW" },
	{ DESKTOP_CREATEMENU, L"DESKTOP_CREATEMENU" },
	{ DESKTOP_HOOKCONTROL, L"DESKTOP_HOOKCONTROL" },
	{ DESKTOP_JOURNALRECORD, L"DESKTOP_JOURNALRECORD" },
	{ DESKTOP_JOURNALPLAYBACK, L"DESKTOP_JOURNALPLAYBACK" },
	{ DESKTOP_ENUMERATE, L"DESKTOP_ENUMERATE" },
	{ DESKTOP_WRITEOBJECTS, L"DESKTOP_WRITEOBJECTS" },
	{ DESKTOP_SWITCHDESKTOP, L"DESKTOP_SWITCHDESKTOP" },
	{ 0, nullptr } };

static perm_t desktopMatch[] = {
	{ 0, nullptr } };

// --------------------------------------------------------------------------------
static perm_t sectionSpecific[] = {
	{ SECTION_QUERY, L"SECTION_QUERY" },
	{ SECTION_MAP_WRITE, L"SECTION_MAP_WRITE" },
	{ SECTION_MAP_READ, L"SECTION_MAP_READ" },
	{ SECTION_MAP_EXECUTE, L"SECTION_MAP_EXECUTE" },
	{ SECTION_EXTEND_SIZE, L"SECTION_EXTEND_SIZE" },
	{ SECTION_MAP_EXECUTE_EXPLICIT, L"SECTION_MAP_EXECUTE_EXPLICIT" },
	{ 0, nullptr } };

static perm_t sectionMatch[] = {
	{ SECTION_ALL_ACCESS, L"SECTION_ALL_ACCESS" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------

static perm_t filemapSpecific[] = {
	{ FILE_MAP_WRITE, L"FILE_MAP_WRITE" },
	{ FILE_MAP_READ, L"FILE_MAP_READ" },
	{ FILE_MAP_EXECUTE, L"FILE_MAP_EXECUTE" },
	{ FILE_MAP_COPY, L"FILE_MAP_COPY" },
	{ FILE_MAP_RESERVE, L"FILE_MAP_RESERVE" },
	{ FILE_MAP_TARGETS_INVALID, L"FILE_MAP_TARGETS_INVALID" },
	{ FILE_MAP_LARGE_PAGES, L"FILE_MAP_LARGE_PAGES" },
	{ 0, nullptr } };

static perm_t filemapMatch[] = {
	{ FILE_MAP_ALL_ACCESS, L"FILE_MAP_ALL_ACCESS" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------

static perm_t evtSpecific[] = {
	{ EVT_READ_ACCESS, L"EVT_READ_ACCESS" },
	{ EVT_WRITE_ACCESS, L"EVT_WRITE_ACCESS" },
	{ EVT_CLEAR_ACCESS, L"EVT_CLEAR_ACCESS" },
	{ 0, nullptr } };

static perm_t evtMatch[] = {
	{ EVT_ALL_ACCESS, L"EVT_ALL_ACCESS" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------

static perm_t tokenSpecific[] = {
	{ TOKEN_ASSIGN_PRIMARY, L"TOKEN_ASSIGN_PRIMARY" },
	{ TOKEN_DUPLICATE, L"TOKEN_DUPLICATE" },
	{ TOKEN_IMPERSONATE, L"TOKEN_IMPERSONATE" },
	{ TOKEN_QUERY, L"TOKEN_QUERY" },
	{ TOKEN_QUERY_SOURCE, L"TOKEN_QUERY_SOURCE" },
	{ TOKEN_ADJUST_PRIVILEGES, L"TOKEN_ADJUST_PRIVILEGES" },
	{ TOKEN_ADJUST_GROUPS, L"TOKEN_ADJUST_GROUPS" },
	{ TOKEN_ADJUST_DEFAULT, L"TOKEN_ADJUST_DEFAULT" },
	{ TOKEN_ADJUST_SESSIONID, L"TOKEN_ADJUST_SESSIONID" },
	{ 0, nullptr } };

static perm_t tokenMatch[] = {
	{ TOKEN_ALL_ACCESS, L"TOKEN_ALL_ACCESS" },
	{ TOKEN_READ, L"TOKEN_READ" },
	{ TOKEN_WRITE, L"TOKEN_WRITE" },
	{ TOKEN_EXECUTE, L"TOKEN_EXECUTE" },
	{ TOKEN_TRUST_CONSTRAINT_MASK, L"TOKEN_TRUST_CONSTRAINT_MASK" },
	{ TOKEN_ACCESS_PSEUDO_HANDLE_WIN8, L"TOKEN_ACCESS_PSEUDO_HANDLE_WIN8" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------

// From km\wdm.h:
// Object Manager Directory Specific Access Rights.

#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)
#define DIRECTORY_CREATE_OBJECT         (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY   (0x0008)

#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

static perm_t objMgrDirectorySpecific[] = {
	{ DIRECTORY_QUERY, L"DIRECTORY_QUERY" },
	{ DIRECTORY_TRAVERSE, L"DIRECTORY_TRAVERSE" },
	{ DIRECTORY_CREATE_OBJECT, L"DIRECTORY_CREATE_OBJECT" },
	{ DIRECTORY_CREATE_SUBDIRECTORY, L"DIRECTORY_CREATE_SUBDIRECTORY" },
	{ 0, nullptr } };

static perm_t objMgrDirectoryMatch[] = {
	{ DIRECTORY_ALL_ACCESS, L"DIRECTORY_ALL_ACCESS" },
	{ 0, nullptr } };

// --------------------------------------------------------------------------------
// The ADS_RIGHT_x values are defined as enums rather than as manifest constant #define values,
// and implicit conversion to DWORD triggers some level-4 warnings that need to be disabled temporarily.
// Examples of those warnings:
//    Warning	C4838	conversion from '__MIDL___MIDL_itf_ads_0001_0048_0001' to 'DWORD' requires a narrowing conversion	SddlHelp	C:\Projects\Utils\SddlHelp\SecurityDescriptorUtils.cpp	339
//    Warning	C4245	'initializing': conversion from '__MIDL___MIDL_itf_ads_0001_0048_0001' to 'DWORD', signed/unsigned mismatch	SddlHelp	C:\Projects\Utils\SddlHelp\SecurityDescriptorUtils.cpp	347
#pragma warning(push)
#pragma warning(disable: 4838)
#pragma warning(disable: 4245)
static perm_t NtdsSpecific[] = {
	{ ADS_RIGHT_DS_CREATE_CHILD, L"ADS_RIGHT_DS_CREATE_CHILD" },
	{ ADS_RIGHT_DS_DELETE_CHILD, L"ADS_RIGHT_DS_DELETE_CHILD" },
	{ ADS_RIGHT_ACTRL_DS_LIST, L"ADS_RIGHT_ACTRL_DS_LIST" },
	{ ADS_RIGHT_DS_SELF, L"ADS_RIGHT_DS_SELF" },
	{ ADS_RIGHT_DS_READ_PROP, L"ADS_RIGHT_DS_READ_PROP" },
	{ ADS_RIGHT_DS_WRITE_PROP, L"ADS_RIGHT_DS_WRITE_PROP" },
	{ ADS_RIGHT_DS_DELETE_TREE, L"ADS_RIGHT_DS_DELETE_TREE" },
	{ ADS_RIGHT_DS_LIST_OBJECT, L"ADS_RIGHT_DS_LIST_OBJECT" },
	{ ADS_RIGHT_DS_CONTROL_ACCESS, L"ADS_RIGHT_DS_CONTROL_ACCESS" },
	{ ADS_RIGHT_DELETE, L"ADS_RIGHT_DELETE" },
	{ ADS_RIGHT_READ_CONTROL, L"ADS_RIGHT_READ_CONTROL" },
	{ ADS_RIGHT_WRITE_DAC, L"ADS_RIGHT_WRITE_DAC" },
	{ ADS_RIGHT_WRITE_OWNER, L"ADS_RIGHT_WRITE_OWNER" },
	{ ADS_RIGHT_SYNCHRONIZE, L"ADS_RIGHT_SYNCHRONIZE" },
	{ ADS_RIGHT_ACCESS_SYSTEM_SECURITY, L"ADS_RIGHT_ACCESS_SYSTEM_SECURITY" },
	{ ADS_RIGHT_GENERIC_READ, L"ADS_RIGHT_GENERIC_READ" },
	{ ADS_RIGHT_GENERIC_WRITE, L"ADS_RIGHT_GENERIC_WRITE" },
	{ ADS_RIGHT_GENERIC_EXECUTE, L"ADS_RIGHT_GENERIC_EXECUTE" },
	{ ADS_RIGHT_GENERIC_ALL, L"ADS_RIGHT_GENERIC_ALL" },
	{ 0, nullptr } };
#pragma warning(pop)

// --------------------------------------------------------------------------------

/// <summary>
/// Returns object-specific perm_t arrays of xSpecific and xMatch values for converting
/// permission bits to corresponding text.
/// </summary>
/// <param name="szObjType">Input: object type from supported set of names</param>
/// <param name="pPermsSpecific">Output: xSpecific array corresponding to object type, if found</param>
/// <param name="pPermsMatch">Output: xMatch array corresponding to object type, if found</param>
/// <returns>true if object type recognized, false otherwise</returns>
static bool GetPermsForType(const wchar_t* szObjType, perm_t*& pPermsSpecific, perm_t*& pPermsMatch)
{
	pPermsSpecific = pPermsMatch = nullptr;

	if (0 == _wcsicmp(szObjType, L"file"))
	{
		pPermsSpecific = fileSpecific;
		pPermsMatch = fileMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"dir"))
	{
		pPermsSpecific = dirSpecific;
		pPermsMatch = fileMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"pipe"))
	{
		pPermsSpecific = pipeSpecific;
		pPermsMatch = fileMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"key"))
	{
		pPermsSpecific = keySpecific;
		pPermsMatch = keyMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"share"))
	{
		pPermsSpecific = shareSpecific;
		pPermsMatch = shareMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"process"))
	{
		pPermsSpecific = processSpecific;
		pPermsMatch = processMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"thread"))
	{
		pPermsSpecific = threadSpecific;
		pPermsMatch = threadMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"service"))
	{
		pPermsSpecific = serviceSpecific;
		pPermsMatch = serviceMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"scm"))
	{
		pPermsSpecific = scmSpecific;
		pPermsMatch = scmMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"com"))
	{
		pPermsSpecific = ComSpecific;
	}
	else
	if (0 == _wcsicmp(szObjType, L"winsta"))
	{
		pPermsSpecific = winstaSpecific;
		pPermsMatch = winstaMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"desktop"))
	{
		pPermsSpecific = desktopSpecific;
		//pPermsMatch = desktopMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"section"))
	{
		pPermsSpecific = sectionSpecific;
		pPermsMatch = sectionMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"filemap"))
	{
		pPermsSpecific = filemapSpecific;
		pPermsMatch = filemapMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"evt"))
	{
		pPermsSpecific = evtSpecific;
		pPermsMatch = evtMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"token"))
	{
		pPermsSpecific = tokenSpecific;
		pPermsMatch = tokenMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"objdir"))
	{
		pPermsSpecific = objMgrDirectorySpecific;
		pPermsMatch = objMgrDirectoryMatch;
	}
	else
	if (0 == _wcsicmp(szObjType, L"ntds"))
	{
		pPermsSpecific = NtdsSpecific;
	}
	else
	if (0 == _wcsicmp(szObjType, L"standard"))
	{
		pPermsSpecific = standardAndGenericMask;
	}
	else
	{
		return false;
	}
	return true;
}

// --------------------------------------------------------------------------------
/// <summary>
/// Output an object-specific textual representation of the input permissions bits.
/// </summary>
/// <param name="sOut">stream to write results into</param>
/// <param name="dwPermissions">Input: 32-bit flags representing the permissions to translate</param>
/// <param name="szObjType">Input: name of the object type that the permissions are supposed to apply to</param>
/// <param name="bOnePermPerLine">Input: whether to put all the permission names on one line or separate lines</param>
/// <param name="sIndent">Input: base indent at which to start writing text</param>
static void OutputPermissions(std::wostream& sOut, DWORD dwPermissions, const wchar_t *szObjType, bool bOnePermPerLine, const std::wstring& sIndent)
{
	// Set up whitespace for formatting, depending on whether perms all on one line or separate lines.
	const wchar_t * szWhitespace = L"           ";
	std::wstring sPrecedingWS, sFollowingWS, sFinal;
	if (bOnePermPerLine)
	{
		sPrecedingWS = sIndent;
		sPrecedingWS += szWhitespace;
		sFollowingWS = L"\n";
		sFinal = L"";
	}
	else
	{
		sPrecedingWS = L"";
		sFollowingWS = L" ";
		sFinal = L"\n";
	}

	// Get the specified object type's object-specific arrays
	perm_t * pPermsSpecific = nullptr, *pPermsMatch = nullptr;
	if (!GetPermsForType(szObjType, pPermsSpecific, pPermsMatch))
	{
		sOut << szWhitespace << L"Unrecognized object type: " << szObjType << std::endl;
		return;
	}

	// First look for an exact match in the object-specific pPermsMatch array (if there is one).
	// If found, output it, and we're done.
	if (pPermsMatch)
	{
		for (perm_t * pPerm = pPermsMatch; pPerm->szName != nullptr; pPerm++)
		{
			if (dwPermissions == pPerm->mask)
			{
				sOut << szWhitespace << pPerm->szName << std::endl;
				return;
			}
		}
	}

	// From this point on, look for bit mask matches and output corresponding text,
	// removing that bit from the permissions and continuing the search.

	// Next step is to look for bit matches in the generic permissions.
	for (perm_t * pPerm = genericMask; pPerm->szName != nullptr; pPerm++)
	{
		if (BitPresent(pPerm->mask, dwPermissions))
		{
			sOut << sPrecedingWS << pPerm->szName << sFollowingWS;
			dwPermissions -= pPerm->mask;
		}
	}
	// Next, look for any matching object-specific permission bits
	if (pPermsSpecific)
	{
		for (perm_t * pPerm = pPermsSpecific; pPerm->szName != nullptr; pPerm++)
		{
			if (BitPresent(pPerm->mask, dwPermissions))
			{
				sOut << sPrecedingWS << pPerm->szName << sFollowingWS;
				dwPermissions -= pPerm->mask;
			}
		}
	}
	// Next, look for any matching standard rights
	for (perm_t * pPerm = standardMask; pPerm->szName != nullptr; pPerm++)
	{
		if (BitPresent(pPerm->mask, dwPermissions))
		{
			sOut << sPrecedingWS << pPerm->szName << sFollowingWS;
			dwPermissions -= pPerm->mask;
		}
	}
	// If any bits haven't been matched, output them in hex.
	if (dwPermissions != 0)
	{
		sOut << sPrecedingWS << HEX(dwPermissions) << sFollowingWS;
	}
	sOut << sFinal;
}

// --------------------------------------------------------------------------------
/// <summary>
/// Returns the address of the SID in an ACE_HEADER (which depends on the ACE type)
/// Returns nullptr if header contains unexpected data.
/// </summary>
static PSID GetAddressOfSidInHeader(const ACE_HEADER* pAceHeader)
{
	switch (pAceHeader->AceType)
	{
		// All of these are ACE_HEADER, ACCESS_MASK, DWORD SidStart:
	case ACCESS_ALLOWED_ACE_TYPE:
	case ACCESS_DENIED_ACE_TYPE:
	case SYSTEM_AUDIT_ACE_TYPE:
	case SYSTEM_ALARM_ACE_TYPE:
	case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
	case ACCESS_DENIED_CALLBACK_ACE_TYPE:
	case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
	case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
	case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
	{
		const ACCESS_ALLOWED_ACE* pACE = (const ACCESS_ALLOWED_ACE*)pAceHeader;
		return (PSID)(&pACE->SidStart);
	}

	// All of these are ACE_HEADER, ACCESS_MASK, DWORD, GUID, GUID, DWORD SidStart:
	case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
	case ACCESS_DENIED_OBJECT_ACE_TYPE:
	case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
	case SYSTEM_ALARM_OBJECT_ACE_TYPE:
	case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
	case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
	case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
	case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
	{
		const ACCESS_ALLOWED_OBJECT_ACE* pACE = (const ACCESS_ALLOWED_OBJECT_ACE*)pAceHeader;
		switch (pACE->Flags)
		{
		case 0:
			return (PSID)(&pACE->ObjectType);
		case ACE_OBJECT_TYPE_PRESENT:
		case ACE_INHERITED_OBJECT_TYPE_PRESENT:
			return (PSID)(&pACE->InheritedObjectType);
		case ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT:
			return (PSID)(&pACE->SidStart);
		default:
			return nullptr;
		}
	}

	default:
		return nullptr;
	}
}

// --------------------------------------------------------------------------------

/// <summary>
/// Given a SID, returns "domain\username (SID)", or "SID" if name conversion fails, or empty string if PSID is nullptr.
/// </summary>
static std::wstring SidToText(PSID psid)
{
	if (nullptr == psid)
		return L"";

	CSid sid(psid);
	std::wstring sDomainUsername = sid.toDomainAndUsername();
	if (sDomainUsername.empty())
		return sid.toSidString();
	else
		return (sid.toDomainAndUsername(true) + L" (" + sid.toSidString() + L")");
}

// --------------------------------------------------------------------------------
/// <summary>
/// Output a textual representation of a DACL or a SACL using object-specific permission names.
/// </summary>
/// <param name="sOut">stream to write results into</param>
/// <param name="bDacl">Input: true for a DACL, false for a SACL</param>
/// <param name="pSD">Input: security descriptor to convert to textual representation</param>
/// <param name="szObjType">Input: name of the object type that the SD applies to</param>
/// <param name="bOnePermPerLine">Input: whether to put all the permission names on one line or separate lines</param>
/// <param name="sIndent">Input: base indent at which to start writing text</param>
static void OutputAcl(std::wostream& sOut, bool bDacl, const PSECURITY_DESCRIPTOR pSD, const wchar_t* szObjType, bool bOnePermPerLine, const std::wstring& sIndent)
{
	PACL pAcl = nullptr;
	BOOL bPresent = FALSE, bDefaulted = FALSE;
	const wchar_t* szAcl = (bDacl ? L"DACL" : L"SACL");

	// Get the DACL or the SACL from the SD
	BOOL ret = bDacl ?
		GetSecurityDescriptorDacl(pSD, &bPresent, &pAcl, &bDefaulted) :
		GetSecurityDescriptorSacl(pSD, &bPresent, &pAcl, &bDefaulted);

	if (!ret)
	{
		DWORD dwLastErr = GetLastError();
		sOut << (bDacl ? L"GetSecurityDescriptorDacl" : L"GetSecurityDescriptorSacl") << L" failed:  " << SysErrorMessage(dwLastErr) << std::endl;
		return;
	}

	// If DACL/SACL not present, output nothing.
	if (!bPresent)
		return;

	// If ACL is present and is NULL, report that.
	if (nullptr == pAcl)
	{
		sOut 
			<< sIndent
			<< (bDacl ? L"NULL DACL (implicit Everyone/FullControl)" : L"NULL SACL") 
			<< std::endl;
		return;
	}

	// If the ACL is not null but not valid, report that.
	if (!IsValidAcl(pAcl))
	{
		sOut << sIndent << L"Invalid " << szAcl << std::endl;
		return;
	}

	ACL_SIZE_INFORMATION aclSizeInfo = { 0 };
	if (!GetAclInformation(pAcl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation))
	{
		// This would be an unusual error at this point, but always check.
		DWORD dwLastErr = GetLastError();
		sOut << L"GetAclInformation error:  " << SysErrorMessage(dwLastErr) << std::endl;
		return;
	}

	sOut << sIndent;
	sOut << L"ACEs in " << szAcl << L":  " << aclSizeInfo.AceCount << std::endl;
	// Check for empty DACL/SACL
	if (0 == aclSizeInfo.AceCount)
	{
		sOut
			<< sIndent
			<< (bDacl ? L"Empty DACL (implicit Deny-All)" : L"Empty SACL")
			<< std::endl;
		return;
	}

	// Iterate through ACEs.
	for (DWORD ix = 0; ix < aclSizeInfo.AceCount; ++ix)
	{
		// Define a union with structures with a lot of common definitions.
		union {
			ACE_HEADER header;
			ACCESS_ALLOWED_ACE allowed;
			ACCESS_DENIED_ACE denied;
			ACCESS_ALLOWED_OBJECT_ACE allowedObject;
			ACCESS_DENIED_OBJECT_ACE deniedObject;
		} *pACE = nullptr;
		if (!GetAce(pAcl, ix, (void**)&pACE))
		{
			DWORD dwLastErr = GetLastError();
			sOut << L"GetAce (" << ix << L") error: " << SysErrorMessage(dwLastErr) << std::endl;
		}
		else
		{
			sOut << sIndent << L"ACE " << ix << L"." << std::endl
				<< sIndent << L"    ";
			// Output ACE type
			const wchar_t* szAceType = AceType(pACE->header.AceType);
			if (szAceType)
				sOut << szAceType;
			else
				sOut << L"[Unknown ACE type: " << HEX(pACE->header.AceType) << L"]";
			sOut << std::endl;

			// Find the SID in the ACE and output it
			sOut << sIndent << L"    SID:   " << SidToText(GetAddressOfSidInHeader(&pACE->header)) << std::endl;

			// Output ACE flags
			DWORD flags = pACE->header.AceFlags;
			sOut << sIndent
				<< L"    Flags: ";
			if (0 == flags)
				sOut << L"None";
			else
			{
				sOut << L"[" << HEX(flags) << L"] ";
				OutputFlagsOnOneLine(sOut, aceFlags, flags);
			}
			sOut << std::endl;

			// Output permissions
			sOut << sIndent
				<< L"    Perms: [" << HEX(pACE->allowed.Mask) << L"] ";
			if (bOnePermPerLine)
				sOut << std::endl;
			if (szObjType)
				OutputPermissions(sOut, pACE->allowed.Mask, szObjType, bOnePermPerLine, sIndent);

		}
	}
}

// --------------------------------------------------------------------------------

/// <summary>
/// Output a textual representation of a security descriptor using object-specific permission names.
/// </summary>
/// <param name="sOut">stream to write results into</param>
/// <param name="pSD">Input: the security descriptor to convert to textual representation</param>
/// <param name="szObjType">Input: name of the object type that the SD applies to</param>
/// <param name="bOnePermPerLine">Input: whether to put all the permission names on one line or separate lines</param>
/// <param name="szIndent">Input: base indent at which to start writing text</param>
void OutputSecurityDescriptor(std::wostream& sOut, PSECURITY_DESCRIPTOR pSD, const wchar_t* szObjType, bool bOnePermPerLine, size_t indent)
{
	// Verify that the input SD is valid
	if (!IsValidSecurityDescriptor(pSD))
	{
		sOut << L"Invalid security descriptor" << std::endl;
		return;
	}

	std::wstring sIndent(indent, L' ');

	// If SDDL is requested, output the SD as SDDL:
	if (szObjType && 0 == _wcsicmp(L"SDDL", szObjType))
	{
		LPWSTR pszSDDL = nullptr;
		ULONG sddlLen = 0;
		SECURITY_INFORMATION si =
			OWNER_SECURITY_INFORMATION |
			GROUP_SECURITY_INFORMATION |
			DACL_SECURITY_INFORMATION |
			SACL_SECURITY_INFORMATION |
			LABEL_SECURITY_INFORMATION;
		BOOL ret = ConvertSecurityDescriptorToStringSecurityDescriptorW(pSD, SDDL_REVISION_1, si, &pszSDDL, &sddlLen);
		if (ret)
		{
			sOut << pszSDDL << std::endl;
			LocalFree((HLOCAL)pszSDDL);
		}
		else
		{
			DWORD dwLastErr = GetLastError();
			sOut << L"Error: " << SysErrorMessage(dwLastErr) << std::endl;
		}
		return;
	}

	// Otherwise, output as detailed, "human-readable" security descriptor with object-specific permission names.
	// Start with the control flags
	SECURITY_DESCRIPTOR_CONTROL sdc;
	DWORD dwRevision;
	if (GetSecurityDescriptorControl(pSD, &sdc, &dwRevision))
	{
		sOut << sIndent;
		sOut << L"Control:  0x" << HEX(sdc) << L"  (";
		OutputFlagsOnOneLine(sOut, controlFlags, sdc);
		sOut << L")" << std::endl;
	}

	// Then the owner
	PSID psid = nullptr;
	BOOL bDefaulted;
	if (GetSecurityDescriptorOwner(pSD, &psid, &bDefaulted))
	{
		if (nullptr != psid)
		{
			sOut << sIndent;
			sOut << L"Owner:    " << SidToText(psid) << std::endl;
		}
	}
	else
	{
		DWORD dwLastErr = GetLastError();
		sOut << L"GetSecurityDescriptorOwner failed:  " << SysErrorMessageWithCode(dwLastErr) << std::endl;
	}

	// Then the primary group
	psid = nullptr;
	if (GetSecurityDescriptorGroup(pSD, &psid, &bDefaulted))
	{
		if (nullptr != psid)
		{
			sOut << sIndent;
			sOut << L"Group:    " << SidToText(psid) << std::endl;
		}
	}
	else
	{
		DWORD dwLastErr = GetLastError();
		sOut << L"GetSecurityDescriptorGroup failed:  " << SysErrorMessageWithCode(dwLastErr) << std::endl;
	}

	// Then the DACL
	OutputAcl(sOut, true, pSD, szObjType, bOnePermPerLine, sIndent);
	// And the SACL
	OutputAcl(sOut, false, pSD, szObjType, bOnePermPerLine, sIndent);
}

// --------------------------------------------------------------------------------

/// <summary>
/// Output a textual representation of a security descriptor using object-specific permission names.
/// </summary>
/// <param name="sOut">stream to write results into</param>
/// <param name="szSDDL">Input: SDDL representing the security descriptor to convert to textual representation</param>
/// <param name="szObjType">Input: name of the object type that the SD applies to</param>
/// <param name="bOnePermPerLine">Input: whether to put all the permission names on one line or separate lines</param>
/// <param name="szIndent">Input: base indent at which to start writing text</param>
void OutputSecurityDescriptor(std::wostream& sOut, const wchar_t* szSDDL, const wchar_t* szObjType, bool bOnePermPerLine, size_t indent)
{
	// Convert the SDDL to a security descriptor, and pass it to the implementation that takes a binary security descriptor
	PSECURITY_DESCRIPTOR pSD = nullptr;
	BOOL ret = ConvertStringSecurityDescriptorToSecurityDescriptorW(szSDDL, SDDL_REVISION_1, &pSD, nullptr);
	if (ret)
	{
		OutputSecurityDescriptor(sOut, pSD, szObjType, bOnePermPerLine, indent);
		LocalFree(pSD);
	}
	else
	{
		DWORD dwLastErr = GetLastError();
		std::wcerr
			<< L"ConvertStringSecurityDescriptorToSecurityDescriptorW failed:" << std::endl
			<< SysErrorMessageWithCode(dwLastErr) << std::endl
			<< L"SDDL = " << szSDDL << std::endl;
	}
}

// --------------------------------------------------------------------------------

/// <summary>
/// Convert a binary security descriptor to SDDL.
/// </summary>
/// <param name="pSD">Input: security descriptor to convert to SDDL</param>
/// <param name="si">Input: Which security information to incorporate into the SDDL</param>
/// <param name="sSDDL">Output: converted SDDL</param>
/// <param name="sErrorInfo">Output: error information, if the function fails</param>
/// <returns>true if successful, false otherwise</returns>
bool SecDescriptorToSDDL(const PSECURITY_DESCRIPTOR pSD, SECURITY_INFORMATION si, std::wstring& sSDDL, std::wstring& sErrorInfo)
{
	sSDDL.clear();
	sErrorInfo.clear();

	wchar_t* pszSddl = nullptr;
	if (ConvertSecurityDescriptorToStringSecurityDescriptorW(pSD, SDDL_REVISION_1, si, &pszSddl, nullptr))
	{
		sSDDL = pszSddl;
		LocalFree(pszSddl);
		return true;
	}
	else
	{
		sErrorInfo = SysErrorMessageWithCode();
		return false;
	}
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------
// SDDL rights lookup

/// <summary>
/// Map SDDL labels to corresponding ACE strings
/// </summary>
struct SddlRight_t
{
	const wchar_t* szLabel;
	const wchar_t* szAceString;
};

static SddlRight_t SddlRights[] = {
	{ L"SDDL_CREATE_CHILD", SDDL_CREATE_CHILD },
	{ L"SDDL_DELETE_CHILD", SDDL_DELETE_CHILD },
	{ L"SDDL_LIST_CHILDREN", SDDL_LIST_CHILDREN },
	{ L"SDDL_SELF_WRITE", SDDL_SELF_WRITE },
	{ L"SDDL_READ_PROPERTY", SDDL_READ_PROPERTY },
	{ L"SDDL_WRITE_PROPERTY", SDDL_WRITE_PROPERTY },
	{ L"SDDL_DELETE_TREE", SDDL_DELETE_TREE },
	{ L"SDDL_LIST_OBJECT", SDDL_LIST_OBJECT },
	{ L"SDDL_CONTROL_ACCESS", SDDL_CONTROL_ACCESS },
	{ L"SDDL_READ_CONTROL", SDDL_READ_CONTROL },
	{ L"SDDL_WRITE_DAC", SDDL_WRITE_DAC },
	{ L"SDDL_WRITE_OWNER", SDDL_WRITE_OWNER },
	{ L"SDDL_STANDARD_DELETE", SDDL_STANDARD_DELETE },
	{ L"SDDL_KEY_WRITE", SDDL_KEY_WRITE },
	{ L"SDDL_KEY_READ", SDDL_KEY_READ },
	{ L"SDDL_KEY_EXECUTE", SDDL_KEY_EXECUTE },
	{ L"SDDL_KEY_ALL", SDDL_KEY_ALL },
	{ L"SDDL_FILE_READ", SDDL_FILE_READ },
	{ L"SDDL_FILE_EXECUTE", SDDL_FILE_EXECUTE },
	{ L"SDDL_FILE_WRITE", SDDL_FILE_WRITE },
	{ L"SDDL_FILE_ALL", SDDL_FILE_ALL },
	{ L"SDDL_GENERIC_ALL", SDDL_GENERIC_ALL },
	{ L"SDDL_GENERIC_EXECUTE", SDDL_GENERIC_EXECUTE },
	{ L"SDDL_GENERIC_WRITE", SDDL_GENERIC_WRITE },
	{ L"SDDL_GENERIC_READ", SDDL_GENERIC_READ },
	};
const size_t nSddlRights = sizeof(SddlRights) / sizeof(SddlRights[0]);

/// <summary>
/// Ensure that the lookup object has been populated. Populate it on first use.
/// </summary>
void SddlRightsLookup::EnsureInitialized()
{
	if (0 == m_rightsLookup.size())
	{
		// For each two-letter code in the SddlRights array, stick it in an SDDL string,
		// convert that string to a security descriptor, and identify the resulting permission 
		// bits. Use those permission bits as the map's key, and the corresponding value the
		// index into the SddlRights array.
		for (size_t ixSddlRight = 0; ixSddlRight < nSddlRights; ++ixSddlRight)
		{
			std::wstringstream strSddl;
			strSddl << L"D:(A;;" << SddlRights[ixSddlRight].szAceString << L";;;BU)";
			PSECURITY_DESCRIPTOR pSD = nullptr;
			BOOL ret = ConvertStringSecurityDescriptorToSecurityDescriptorW(strSddl.str().c_str(), SDDL_REVISION_1, &pSD, nullptr);
			if (ret)
			{
				PACL pDacl = nullptr;
				BOOL bDaclPresent = FALSE, bDaclDefaulted = FALSE;
				if (GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted))
				{
					ACCESS_ALLOWED_ACE* pAce = nullptr;
					if (GetAce(pDacl, 0, (LPVOID*)&pAce))
					{
						ACCESS_MASK permBits = pAce->Mask;

						if (m_rightsLookup.end() == m_rightsLookup.find(permBits))
						{
							m_rightsLookup[permBits] = ixSddlRight;
						}
					}
				}
				LocalFree(pSD);
			}
			else
			{
				DWORD dwLastErr = GetLastError();
				std::wcerr
					<< L"ConvertStringSecurityDescriptorToSecurityDescriptorW failed:" << std::endl
					<< SysErrorMessageWithCode(dwLastErr) << std::endl
					<< L"SDDL = " << strSddl.str() << std::endl;
			}
		}
	}
}

bool SddlRightsLookup::Lookup(std::wostream& sOut, const wchar_t* szOption)
{
	// Make sure the lookup object is populated.
	EnsureInitialized();

	// For "sddl" just output the content of the lookup table.
	if (0 == _wcsicmp(szOption, L"sddl"))
	{
		for (
			SddlRightsLookup_t::const_iterator iterRights = m_rightsLookup.begin();
			iterRights != m_rightsLookup.end();
			++iterRights
			)
		{
			ACCESS_MASK permBits = iterRights->first;
			size_t ixSddlRight = iterRights->second;
			sOut
				<< std::right
				<< HEX(permBits, 8, false, true)
				<< std::left
				<< L"  "
				<< SddlRights[ixSddlRight].szAceString
				<< L"  "
				<< SddlRights[ixSddlRight].szLabel
				<< std::endl;
		}
	}
	else
	{
		// For all other object types, output values corresponding with the xSpecific and xMatch tables
		perm_t* pPermsSpecific = nullptr, * pPermsMatch = nullptr;
		if (!GetPermsForType(szOption, pPermsSpecific, pPermsMatch))
		{
			std::wcerr << L"Unrecognized rights option: " << szOption << std::endl;
			return false;
		}

		if (pPermsSpecific)
		{
			for (perm_t* pPerm = pPermsSpecific; pPerm->szName != nullptr; pPerm++)
			{
				SddlRightsLookup_t::const_iterator iterRights = m_rightsLookup.find(pPerm->mask);
				const wchar_t* szAceString = (m_rightsLookup.end() != iterRights) ? SddlRights[iterRights->second].szAceString : L"  ";
				sOut
					<< std::right
					<< HEX(pPerm->mask, 8, false, true)
					<< std::left
					<< L"  "
					<< szAceString
					<< L"  "
					<< pPerm->szName
					<< std::endl;
			}
		}
		if (pPermsMatch)
		{
			for (perm_t* pPerm = pPermsMatch; pPerm->szName != nullptr; pPerm++)
			{
				SddlRightsLookup_t::const_iterator iterRights = m_rightsLookup.find(pPerm->mask);
				const wchar_t* szAceString = (m_rightsLookup.end() != iterRights) ? SddlRights[iterRights->second].szAceString : L"  ";
				sOut
					<< std::right
					<< HEX(pPerm->mask, 8, false, true)
					<< std::left
					<< L"  "
					<< szAceString
					<< L"  "
					<< pPerm->szName
					<< std::endl;
			}
		}
	}

	return true;
}

// --------------------------------------------------------------------------------
// --------------------------------------------------------------------------------

/// <summary>
/// For a given SID (e.g., "S-1-5-32-544") or SDDL SID string (e.g., "BA") 
/// output the SDDL SID string, the SID, and the (possibly) localized domain\username.
/// </summary>
/// <param name="sOut">stream to write results into</param>
/// <param name="szSidOption">SID or SDDL SID string</param>
/// <returns>true if successful, false otherwise</returns>
bool SidLookup(std::wostream& sOut, const wchar_t* szSidOption)
{
	if (nullptr == szSidOption)
		return false;

	// Build an SDDL string incorporating the input SID (e.g., "S-1-5-32-544") or SID string (e.g., "BA"); 
	// convert that SDDL to a security descriptor and then convert that security descriptor back to an SDDL string.
	// Extract the SID part from that SDDL -- if it's two characters long, then that's the SDDL SID string.
	// From the binary security descriptor, extract the SID, and get the domain\username from it. Output all of them.
	std::wstringstream strSddl;
	strSddl << L"D:(A;;GA;;;" << szSidOption << L")";
	PSECURITY_DESCRIPTOR pSD = NULL;
	BOOL ret = ConvertStringSecurityDescriptorToSecurityDescriptorW(strSddl.str().c_str(), SDDL_REVISION_1, &pSD, NULL);
	if (ret)
	{
		wchar_t* pszSddl = NULL;
		ret = ConvertSecurityDescriptorToStringSecurityDescriptorW(pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &pszSddl, NULL);
		if (ret)
		{
			// Parse the SDDL
			std::vector<std::wstring> vElems;
			SplitStringToVector(pszSddl, L';', vElems);
			// Validate the resulting number of semicolon-delimited strings.
			if (6 != vElems.size())
			{
				std::wcerr << L"Unexpected SDDL conversion: " << pszSddl << std::endl;
			}
			else
			{
				std::wstring sSddlSidString;

				// The SID specifier is the last item in the ACE and is followed by a ")", so if it's
				// three characters, the first two are the SDDL SID string.
				if (3 == vElems[5].length())
				{
					sSddlSidString = vElems[5].substr(0, vElems[5].length() - 1);
				}

				// Get the SID from the binary security descriptor.
				PACL pDacl = NULL;
				BOOL bDaclPresent = FALSE, bDaclDefaulted = FALSE;
				if (GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted))
				{
					ACCESS_ALLOWED_ACE* pAce = NULL;
					if (GetAce(pDacl, 0, (LPVOID*)&pAce))
					{
						PSID pSid = (PSID)(&pAce->SidStart);
						CSid sid(pSid);
						// Formatted output with the SDDL SID string (if there is one), the SID, and the domain\username.
						sOut
							<< std::left
							<< std::setw(4)
							<< sSddlSidString
							<< std::setw(15)
							<< sid.toSidString()
							<< sid.toDomainAndUsername()
							<< std::endl;
					}
				}
			}

			LocalFree(pszSddl);
		}
		else
		{
			DWORD dwLastErr = GetLastError();
			std::wcerr
				<< L"ConvertSecurityDescriptorToStringSecurityDescriptorW failed:" << std::endl
				<< SysErrorMessageWithCode(dwLastErr) << std::endl
				<< L"Test SDDL = " << strSddl.str() << std::endl;
		}

		LocalFree(pSD);
	}
	else
	{
		DWORD dwLastErr = GetLastError();
		std::wcerr
			<< L"ConvertSecurityDescriptorToStringSecurityDescriptorW failed:" << std::endl
			<< SysErrorMessageWithCode(dwLastErr) << std::endl
			<< L"Test SDDL = " << strSddl.str() << std::endl;
	}

	return true;
}

