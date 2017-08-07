#ifndef HTYPES_H
#define HTYPES_H
#include <windows.h>

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

struct HookRecordEx
{
	void* FunctionHook = NULL;
	void* HookFunction = NULL;
	const char* FunctionHookData;
	const char* ProcessName;
	HANDLE Process;
	unsigned char OriginBytes[5];
};

#endif
