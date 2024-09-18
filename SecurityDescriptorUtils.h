#pragma once

#include <Windows.h>
#include <map>
#include <vector>
#include <string>
#include <iostream>

// --------------------------------------------------------------------------------

/// <summary>
/// Output a textual representation of a security descriptor using object-specific permission names.
/// </summary>
/// <param name="sOut">stream to write results into</param>
/// <param name="pSD">Input: the security descriptor to convert to textual representation</param>
/// <param name="szObjType">Input: name of the object type that the SD applies to</param>
/// <param name="bOnePermPerLine">Input: whether to put all the permission names on one line or separate lines</param>
/// <param name="szIndent">Input: base indent at which to start writing text</param>
void OutputSecurityDescriptor(std::wostream& sOut, PSECURITY_DESCRIPTOR pSD, const wchar_t* szObjType, bool bOnePermPerLine = true, size_t indent = 0);

/// <summary>
/// Output a textual representation of a security descriptor using object-specific permission names.
/// </summary>
/// <param name="sOut">stream to write results into</param>
/// <param name="szSDDL">Input: SDDL representing the security descriptor to convert to textual representation</param>
/// <param name="szObjType">Input: name of the object type that the SD applies to</param>
/// <param name="bOnePermPerLine">Input: whether to put all the permission names on one line or separate lines</param>
/// <param name="szIndent">Input: base indent at which to start writing text</param>
void OutputSecurityDescriptor(std::wostream& sOut, const wchar_t* szSDDL, const wchar_t* szObjType, bool bOnePermPerLine = true, size_t indent = 0);

/// <summary>
/// Convert a binary security descriptor to SDDL.
/// </summary>
/// <param name="pSD">Input: security descriptor to convert to SDDL</param>
/// <param name="si">Input: Which security information to incorporate into the SDDL</param>
/// <param name="sSDDL">Output: converted SDDL</param>
/// <param name="sErrorInfo">Output: error information, if the function fails</param>
/// <returns>true if successful, false otherwise</returns>
bool SecDescriptorToSDDL(const PSECURITY_DESCRIPTOR pSD, SECURITY_INFORMATION si, std::wstring& sSDDL, std::wstring& sErrorInfo);

// --------------------------------------------------------------------------------

/// <summary>
/// Class to enable looking up of SDDL rights based on permissions masks
/// </summary>
class SddlRightsLookup
{
public:
	SddlRightsLookup() = default;
	~SddlRightsLookup() = default;

	bool Lookup(std::wostream& sOut, const wchar_t* szOption);

private:
	// Maps permission bits to a table that has the corresponding SDDL two-letter
	// code and its associated name.
	typedef std::map<ACCESS_MASK, size_t> SddlRightsLookup_t;
	SddlRightsLookup_t m_rightsLookup;
	void EnsureInitialized();

private:
	SddlRightsLookup(const SddlRightsLookup&) = delete;
	SddlRightsLookup& operator = (const SddlRightsLookup&) = delete;
};

// --------------------------------------------------------------------------------

/// <summary>
/// For a given SID (e.g., "S-1-5-32-544") or SDDL SID string (e.g., "BA") 
/// output the SDDL SID string, the SID, and the (possibly) localized domain\username.
/// </summary>
/// <param name="sOut">stream to write results into</param>
/// <param name="szSidOption">SID or SDDL SID string</param>
/// <returns>true if successful, false otherwise</returns>
bool SidLookup(std::wostream& sOut, const wchar_t* szSidOption);
