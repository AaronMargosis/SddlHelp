// SddlHelp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <LM.h> // to get max domain and username lengths
#include <sddl.h>
#include <iostream>
#include <sstream>
#include <map>
#include <vector>
#include "HEX.h"

#include "SecurityDescriptorUtils.h"
#include "StringUtils.h"

//TODO: see below for lists of other object rights that this tool could cover

struct opts_t
{
	const wchar_t* szOption;
	const wchar_t* szDescription;
};

opts_t options[] = {
	{ L"sddl" ,    L"Listing of all SDDL two-letter access rights codes and name of constant" },
	{ L"ntds",     L"Mapping of AD Directory Services constants to defined SDDL codes" },
	{ L"file" ,    L"Mapping of file permission constants to defined SDDL codes" },
	{ L"dir" ,     L"Mapping of directory (file system) permission constants to defined SDDL codes" },
	{ L"pipe" ,    L"Mapping of pipe permission constants to defined SDDL codes" },
	{ L"key" ,     L"Mapping of registry key permission constants to defined SDDL codes" },
	{ L"service" , L"Mapping of service permission constants to defined SDDL codes" },
	{ L"scm" ,     L"Mapping of service control manager permission constants to defined SDDL codes" },
	{ L"process" , L"Mapping of process permission constants to defined SDDL codes" },
	{ L"thread" ,  L"Mapping of thread permission constants to defined SDDL codes" },
	{ L"evt" ,     L"Mapping of Windows event log permission constants to defined SDDL codes" },
	{ L"share" ,   L"Mapping of file share permission constants to defined SDDL codes" },
	{ L"com" ,     L"Mapping of COM permission constants to defined SDDL codes" },
	{ L"winsta" ,  L"Mapping of window station permission constants to defined SDDL codes" },
	{ L"desktop" , L"Mapping of desktop permission constants to defined SDDL codes" },
	{ L"section" , L"Mapping of section permission constants to defined SDDL codes" },
	{ L"filemap" , L"Mapping of file mapping permission constants to defined SDDL codes" },
	{ L"token" ,   L"Mapping of token permission constants to defined SDDL codes" },
	{ L"objdir" ,  L"Mapping of object manager directory permission constants to defined SDDL codes" },
	{ L"standard", L"Mapping of standard and generic permission constants to defined SDDL codes" },
	{ nullptr, nullptr }
};

void Usage(const wchar_t* argv0)
{
	std::wstring sExe = GetFileNameFromFilePath(argv0);
	std::wcerr
		<< L"Usage:" << std::endl
		<< std::endl
		<< L"  " << sExe << L"  -sid sidSpec [...]" << std::endl
		<< L"  " << sExe << L"  -rights objType [...]" << std::endl
		<< L"  " << sExe << L"  -translate sddlString [objType]" << std::endl
		<< std::endl
		<< L"With \"-sid\", \"sidSpec\" is one or more SIDs or SDDL string SID codes; examples:" << std::endl
		<< L"    " << sExe << L" -sid BA" << std::endl
		<< L"    " << sExe << L" -sid S-1-5-18" << std::endl
		<< L"    " << sExe << L" -sid S-1-1-0 LS BU" << std::endl
		<< std::endl
		<< L"With \"-rights\", \"objType\" is one or more of:" << std::endl
		;
	for (opts_t* pOption = options; pOption->szOption != nullptr; pOption++)
	{
		std::wcerr
			<< std::left
			<< std::setw(4)
			<< L""
			<< std::setw(10)
			<< pOption->szOption
			<< pOption->szDescription
			<< std::endl;
	}
	std::wcerr
		<< L"  Examples:" << std::endl
		<< L"    " << sExe << L" -rights key" << std::endl
		<< L"    " << sExe << L" -rights file standard | sort" << std::endl
		<< std::endl;
	std::wcerr
		<< L"With \"-translate\", \"sddlString\" is an SDDL string and optional \"objType\" is an objType listed above." << std::endl
		<< L"  Examples:" << std::endl
		<< L"    " << sExe << L" -translate \"O:SYD:PAI(D;;CC;;;WD)(A;;0x1200a9;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)\" dir" << std::endl
		<< L"    " << sExe << L" -translate \"O:BAD:(A;CI;KA;;;SY)(A;CI;RCWD;;;BA)S:AINO_ACCESS_CONTROL\" key" << std::endl
		<< std::endl;
	exit(-1);
}


// --------------------------------------------------------------------------------

int wmain(int argc, wchar_t** argv)
{
	// Options
	bool bSidLookup = false, bRightsLookup = false, bTranslate = false;

	// Parse command line options
	if (argc < 3)
		Usage(argv[0]);

	// First param must be -sid, -rights, or -translate
	if (0 == _wcsicmp(L"-sid", argv[1]))
	{
		bSidLookup = true;
	}
	else
	if (0 == _wcsicmp(L"-rights", argv[1]))
	{
		bRightsLookup = true;
	}
	else
	if (0 == _wcsicmp(L"-translate", argv[1]))
	{
		bTranslate = true;
	}
	else
	{
		Usage(argv[0]);
	}
	
	if (bRightsLookup)
	{
		SddlRightsLookup rightsLookup;
		for (int ixArg = 2; ixArg < argc; ++ixArg)
		{
			rightsLookup.Lookup(std::wcout, argv[ixArg]);
		}
	}
	else if (bSidLookup)
	{
		for (int ixArg = 2; ixArg < argc; ++ixArg)
		{
			SidLookup(std::wcout, argv[ixArg]);
		}
	}
	else if (bTranslate)
	{
		const wchar_t* szSDDL = argv[2];
		const wchar_t* szObjType = (4 == argc) ? argv[3] : NULL;
		OutputSecurityDescriptor(std::wcout, szSDDL, szObjType);
	}
	else
	{
		// Should be impossible to get here.
		std::wcerr << L"Dumb program error" << std::endl;
	}

	return 0;
}

/*
TODO: more object rights that this tool could cover

#include <ClusApi.h>
#include <memoryapi.h>
#include <ntlsa.h>
#include <NTSecAPI.h>
#include <synchapi.h>
#include <wincrypt.h>
#include <winevt.h>
#include <WinFax.h>
#include <winnt.h>
#include <winspool.h>
#include <winsvc.h>
#include <WinUser.h>
#include <WtsApi32.h>

x_ALL_ACCESS -- look these up and find the other rights associated with the same objects:

	// synchronization objects (winnt.h)
	EVENT_ALL_ACCESS,
	MUTANT_ALL_ACCESS,
	SEMAPHORE_ALL_ACCESS,
	TIMER_ALL_ACCESS,
	// other winnt.h:
	IO_COMPLETION_ALL_ACCESS,
	JOB_OBJECT_ALL_ACCESS,
	MEMORY_PARTITION_ALL_ACCESS,
	SESSION_ALL_ACCESS,
	// kernel transaction manager (winnt.h):
	ENLISTMENT_ALL_ACCESS,
	RESOURCEMANAGER_ALL_ACCESS,
	TRANSACTION_ALL_ACCESS,
	TRANSACTIONMANAGER_ALL_ACCESS,
	// ClusApi.h:
	CLUSAPI_ALL_ACCESS,
	// WinFax.h
	FAX_ALL_ACCESS,
	// spooler (winspool.h)
	JOB_ALL_ACCESS,
	PRINTER_ALL_ACCESS,
	SERVER_ALL_ACCESS,
	// for WTSCreateListener (WtsApi32.h)
	WTS_SECURITY_ALL_ACCESS,
	// LSA (ntlsa.h)
	ACCOUNT_ALL_ACCESS,
	POLICY_ALL_ACCESS,
	SECRET_ALL_ACCESS,
	TRUSTED_ALL_ACCESS,

Some specific rights, then aggregated names for the same object type:

//
EVENT_MODIFY_STATE
EVENT_ALL_ACCESS
//
MUTANT_QUERY_STATE
MUTANT_ALL_ACCESS
//
SEMAPHORE_MODIFY_STATE
SEMAPHORE_ALL_ACCESS
//
TIMER_QUERY_STATE TIMER_MODIFY_STATE
TIMER_ALL_ACCESS
//
IO_COMPLETION_MODIFY_STATE
IO_COMPLETION_ALL_ACCESS
//
JOB_OBJECT_ASSIGN_PROCESS JOB_OBJECT_SET_ATTRIBUTES JOB_OBJECT_QUERY JOB_OBJECT_TERMINATE JOB_OBJECT_SET_SECURITY_ATTRIBUTES JOB_OBJECT_IMPERSONATE
JOB_OBJECT_ALL_ACCESS
//
MEMORY_PARTITION_QUERY_ACCESS MEMORY_PARTITION_MODIFY_ACCESS
MEMORY_PARTITION_ALL_ACCESS
//
FAX_JOB_SUBMIT FAX_JOB_QUERY FAX_CONFIG_QUERY FAX_CONFIG_SET FAX_PORT_QUERY FAX_PORT_SET FAX_JOB_MANAGE
FAX_READ FAX_WRITE FAX_ALL_ACCESS
//
WTS_SECURITY_QUERY_INFORMATION WTS_SECURITY_SET_INFORMATION WTS_SECURITY_RESET WTS_SECURITY_VIRTUAL_CHANNELS WTS_SECURITY_REMOTE_CONTROL WTS_SECURITY_LOGON WTS_SECURITY_LOGOFF WTS_SECURITY_MESSAGE WTS_SECURITY_CONNECT WTS_SECURITY_DISCONNECT
WTS_SECURITY_GUEST_ACCESS WTS_SECURITY_CURRENT_GUEST_ACCESS WTS_SECURITY_USER_ACCESS WTS_SECURITY_CURRENT_USER_ACCESS WTS_SECURITY_ALL_ACCESS
//
*/
