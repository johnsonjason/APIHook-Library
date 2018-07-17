#include "stdafx.h"
#include "chooks.h"

static std::vector<hook_record> hook_records;

std::int32_t hook_function(void* function_origin, void* function_end, std::string function_hook_data)
{
	hook_record function_record = { 0 };
	function_record.function_hook = function_origin;
	function_record.hook_function = function_end;
	function_record.function_hook_data = function_hook_data;
	std::memcpy(function_record.origin_bytes, function_origin, 5);

	hook_records.push_back(function_record);

	std::uint32_t old_protection;

	if (VirtualProtect(function_record.function_hook, 1, static_cast<std::uint32_t>(dbg_redef::page_protection::page_rwx),
		reinterpret_cast<unsigned long*>(&old_protection)) == 0)
	{
		return GetLastError();
	}

	std::uint32_t origin = reinterpret_cast<std::uint32_t>(function_record.function_hook);
	std::uint32_t end = reinterpret_cast<std::uint32_t>(function_record.hook_function);

	*reinterpret_cast<std::uint8_t*>(function_record.function_hook) = 0xE9;
	*reinterpret_cast<std::uint32_t*>(origin + 1) = (end - origin) - 5;

	if (VirtualProtect(function_record.function_hook, 1, old_protection, reinterpret_cast<unsigned long*>(&old_protection)) == 0)
	{
		return GetLastError();
	}

	std::size_t cmp_relation = std::memcmp(function_record.origin_bytes, function_record.function_hook, 5);
	if (cmp_relation != 0)
	{
		return cmp_relation;
	}

	return 0;
}

std::int32_t rehook_function(std::string function_hook_data)
{
	hook_record function_record = { 0 };

	for (std::size_t record_iterator = 0; record_iterator < hook_records.size(); record_iterator++)
	{
		if (function_hook_data.compare(hook_records[record_iterator].function_hook_data) == 0)
		{
			function_record = hook_records[record_iterator];
			break;
		}
	}

	if (function_record.hook_function == nullptr)
	{
		return -1;
	}

	std::uint32_t old_protection;

	if (VirtualProtect(function_record.function_hook, 1, static_cast<std::uint32_t>(dbg_redef::page_protection::page_rwx),
		reinterpret_cast<unsigned long*>(&old_protection)) == 0)
	{
		return GetLastError();
	}

	std::uint32_t origin = reinterpret_cast<std::uint32_t>(function_record.function_hook);
	std::uint32_t end = reinterpret_cast<std::uint32_t>(function_record.hook_function);

	*reinterpret_cast<std::uint8_t*>(function_record.function_hook) = 0xE9;
	*reinterpret_cast<std::uint32_t*>(origin + 1) = (end - origin) - 5;

	if (VirtualProtect(function_record.function_hook, 1, old_protection, reinterpret_cast<unsigned long*>(&old_protection)) == 0)
	{
		return GetLastError();
	}

	std::size_t cmp_relation = std::memcmp(function_record.origin_bytes, function_record.function_hook, 5);
	if (cmp_relation != 0)
	{
		return cmp_relation;
	}

	return 0;
}

std::int32_t temp_unhook_function(std::string function_hook_data)
{
	hook_record function_record = { 0 };

	for (std::size_t record_iterator = 0; record_iterator < hook_records.size(); record_iterator++)
	{
		if (function_hook_data.compare(hook_records[record_iterator].function_hook_data) == 0)
		{
			function_record = hook_records[record_iterator];
			break;
		}
	}

	if (function_record.hook_function == nullptr)
	{
		return -1;
	}

	std::uint32_t old_protection;

	if (VirtualProtect(function_record.function_hook, 1, static_cast<std::uint32_t>(dbg_redef::page_protection::page_rwx),
		reinterpret_cast<unsigned long*>(&old_protection)) == 0)
	{
		return GetLastError();
	}

	std::memcpy(function_record.function_hook, function_record.origin_bytes, 5);

	if (VirtualProtect(function_record.function_hook, 1, old_protection, reinterpret_cast<unsigned long*>(&old_protection)) == 0)
	{
		return GetLastError();
	}

	std::size_t cmp_relation = std::memcmp(function_record.function_hook, function_record.origin_bytes, 5);
	if (cmp_relation != 0)
	{
		return cmp_relation;
	}

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
		return -1;

	DWORD FormerPageRight;

	if (VirtualProtect(FunctionOrigin, 1, PAGE_EXECUTE_READWRITE, &FormerPageRight) == 0)
		return GetLastError();

	if (memcpy(FunctionOrigin, FunctionRecord.OriginBytes, 5) != FunctionOrigin)
		return -3;

	if (VirtualProtect(FunctionOrigin, 1, FormerPageRight, &FormerPageRight) == 0)
		return GetLastError();

	if (memcmp(FunctionOrigin, FunctionRecord.OriginBytes, 5) != 0)
		return -2;

	HookRecords.erase(HookRecords.begin() + HookIndex);

	return 0;
}
