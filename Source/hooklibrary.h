#include "stdafx.h"
#include <vector>
#include <windows.h>
#include <TlHelp32.h>

struct AddressRecord
{
	void* Address;
	const char* AddressData;
};

struct HookRecord
{
	void* FunctionHook = NULL;
	void* HookFunction = NULL;
	const char* FunctionHookData;
	unsigned char OriginBytes[5];
};

std::vector<HookRecord> HookRecords = {};

DWORD FindProcessIdFromProcessName(const std::wstring processName) {
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile)) {
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo)) {
		if (!processName.compare(processInfo.szExeFile)) {
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

DWORD GetModuleBase(const DWORD dwProcessId, LPCWSTR szModuleName)
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (!hSnap)
	{
		return 0;
	}
	MODULEENTRY32 me;
	me.dwSize = sizeof(MODULEENTRY32);
	DWORD dwReturn = 0;
	if (Module32First(hSnap, &me))
	{
		do
		{
			if (lstrcmpi(me.szModule, szModuleName) == 0)
			{
				dwReturn = (DWORD)me.modBaseAddr;
				break;
			}
		} while (Module32Next(hSnap, &me));
	}
	CloseHandle(hSnap);
	return dwReturn;
}

int HookFunction(void* FunctionOrigin, void* FunctionEnd, const char* FunctionHookData)
{
	HookRecord FunctionRecord;
	FunctionRecord.FunctionHook = FunctionOrigin;
	FunctionRecord.HookFunction = FunctionEnd;
	FunctionRecord.FunctionHookData = FunctionHookData;
	memcpy(FunctionRecord.OriginBytes, FunctionOrigin, 5);

	HookRecords.push_back(FunctionRecord);

	DWORD FormerPageRight;

	if (VirtualProtect(FunctionOrigin, 1, PAGE_EXECUTE_READWRITE, &FormerPageRight) == 0)
		return 1001;

	DWORD Origin = (DWORD)FunctionOrigin;
	DWORD End = (DWORD)FunctionEnd;

	*(BYTE*)FunctionOrigin = 0xE9;
	*(DWORD*)(Origin + 1) = (End - Origin) - 5;

	if (VirtualProtect(FunctionOrigin, 1, FormerPageRight, &FormerPageRight) == 0)
		return 1002;

	if (memcmp(FunctionRecord.OriginBytes, FunctionOrigin, 5) != 0)
		return 4;

	return 0;
}

int RehookFunction(void* FunctionOrigin, void* FunctionEnd, const char* FunctionHookData)
{
	HookRecord FunctionRecord;

	for (size_t RecordIterator = 0; RecordIterator < HookRecords.size(); RecordIterator++)
	{
		if (strncmp(HookRecords[RecordIterator].FunctionHookData, FunctionHookData, strlen(FunctionHookData)) == 0)
		{
			FunctionRecord = HookRecords[RecordIterator];
			break;
		}
	}

	if (FunctionRecord.HookFunction == NULL)
		return 10;

	DWORD FormerPageRight;

	if (VirtualProtect(FunctionOrigin, 1, PAGE_EXECUTE_READWRITE, &FormerPageRight) == 0)
		return 1001;

	DWORD Origin = (DWORD)FunctionOrigin;
	DWORD End = (DWORD)FunctionEnd;

	*(BYTE*)FunctionOrigin = 0xE9;
	*(DWORD*)(Origin + 1) = (End - Origin) - 5;

	if (VirtualProtect(FunctionOrigin, 1, FormerPageRight, &FormerPageRight) == 0)
		return 1002;

	if (memcmp(FunctionRecord.OriginBytes, FunctionOrigin, 5) != 0)
		return 4;

	return 0;
}

int TempUnhookFunction(void* FunctionOrigin, const char* FunctionHookData)
{
	HookRecord FunctionRecord;

	for (size_t RecordIterator = 0; RecordIterator < HookRecords.size(); RecordIterator++)
	{
		if (strncmp(HookRecords[RecordIterator].FunctionHookData, FunctionHookData, strlen(FunctionHookData)) == 0)
		{
			FunctionRecord = HookRecords[RecordIterator];
			break;
		}
	}

	if (FunctionRecord.HookFunction == NULL)
		return 10;

	DWORD FormerPageRight;

	if (VirtualProtect(FunctionOrigin, 1, PAGE_EXECUTE_READWRITE, &FormerPageRight) == 0)
		return 1001;

	if (memcpy(FunctionOrigin, FunctionRecord.OriginBytes, 5) != FunctionOrigin)
		return 2;

	if (VirtualProtect(FunctionOrigin, 1, FormerPageRight, &FormerPageRight) == 0)
		return 1002;

	if (memcmp(FunctionOrigin, FunctionRecord.OriginBytes, 5) != 0)
		return 4;

	return 0;
}

int UnhookFunction(void* FunctionOrigin, void* FunctionEnd, const char* FunctionHookData)
{
	HookRecord FunctionRecord;
	size_t HookIndex = 0;
	
	for (size_t RecordIterator = 0; RecordIterator < HookRecords.size(); RecordIterator++)
	{
		if (strncmp(HookRecords[RecordIterator].FunctionHookData, FunctionHookData, strlen(FunctionHookData)) == 0)
		{
			HookIndex = RecordIterator;
			FunctionRecord = HookRecords[RecordIterator];
			break;
		}
	}

	if (FunctionRecord.HookFunction == NULL)
		return 10;

	DWORD FormerPageRight;

	if (VirtualProtect(FunctionOrigin, 1, PAGE_EXECUTE_READWRITE, &FormerPageRight) == 0)
		return 1001;

	if (memcpy(FunctionOrigin, FunctionRecord.OriginBytes, 5) != FunctionOrigin)
		return 2;

	if (VirtualProtect(FunctionOrigin, 1, FormerPageRight, &FormerPageRight) == 0)
		return 1002;

	if (memcmp(FunctionOrigin, FunctionRecord.OriginBytes, 5) != 0)
		return 4;

	HookRecords.erase(HookRecords.begin() + HookIndex);
	return 0;
}

