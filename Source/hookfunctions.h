#ifndef HOOKFUNCTIONS_H
#define HOOKFUNCTIONS_H

#include "htypes.h"
#include <windows.h>

std::vector<HookRecord> HookRecords;
std::vector<HookRecordEx> HookRecordsEx;

int HookFunction(void* FunctionOrigin, void* FunctionEnd, const char* FunctionHookData);

int RehookFunction(void* FunctionOrigin, void* FunctionEnd, const char* FunctionHookData);

int TempUnhookFunction(void* FunctionOrigin, const char* FunctionHookData);

int UnhookFunction(void* FunctionOrigin, void* FunctionEnd, const char* FunctionHookData);

#endif
