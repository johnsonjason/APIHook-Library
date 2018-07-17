#include "stdafx.h"
#include <Windows.h>
#include "chooks.h"
#define UNDEFINED 0

const void* table_packet = UNDEFINED

BOOL WINAPI hook_getmessage_a(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax )
{
	temp_unhook_function("user32:getmessagea");
	BOOL test_retn = GetMessageA(lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax);
	if (lpMsg->message >= 256 && lpMsg->message <= 257)
	{
		switch (lpMsg->wParam)
		{
		case VK_LEFT:
			__asm push 0x66;
			__asm jmp table_packet;
			break;
		case VK_UP:
			__asm push 0x65;
			__asm jmp table_packet;
			break;
		case VK_RIGHT:
			__asm push 0x68;
			__asm jmp table_packet;
			break;
		case VK_DOWN:
			__asm push 0x67;
			__asm jmp table_packet;
			break;
		}
		lpMsg->message = NULL;
		lpMsg->wParam = NULL;
	}
	rehook_function("user32:getmessagea");
	return test_retn;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hook_function(GetProcAddress(GetModuleHandleA("user32.dll"), "GetMessageA"),
		hook_getmessage_a, "user32:getmessagea");
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
