// By jasonfish4

#include "chooks.h"
#include <winsock.h>
#pragma comment(lib, "ws2_32.lib")

extern "C" int (WINAPI *psendto)(SOCKET socket, const char* buffer, int length, int flags, const struct sockaddr *to, int tolen) = sendto; // original function to call
PVOID SendFunc = GetProcAddress(GetModuleHandleA("ws2_32.dll"), "sendto"); // Obtain a pointer to the sendto function in ws2_32.dll

volatile BOOL g_Captured = FALSE; // Check if the specific packet has been captured or not

/*
* Function to capture packets
* If the packet has a length of 51, accept and return
*/

int WINAPI CapturePacket(SOCKET socket, const char* buffer, int length, int flags, const struct sockaddr* to, int tolen)
{
	// If packet has a length of 51
	if (length == 51)
		g_Captured = true; // Set g_Captured to true since the condition is true
	
	TempUnhookFunction(SendFunc, "winsock:sendto"); // Unhook the function to perform an __stdcall on sendto without recursively jumping back here
	int result = psendto(socket, buffer, length, flags, to, tolen); // _stdcall sendto
	RehookFunction(SendFunc, CapturePacket, "winsock:sendto"); // Rehook the function

	return result; // Return the expected result
}

DWORD WINAPI HookControl(LPVOID lpParam)
{
	HookFunction(SendFunc, CapturePacket, "winsock:sendto"); // Hook the function and setup a symbolic name that can be referenced

	// While g_Captured is false, Sleep for 1 millisecond to give the OS time to handle many other resources and not waste CPU
  while (!g_Captured) 
		Sleep(1); // I should be using a semaphore, but I'm lazy
    
	UnhookFunction(SendFunc, CapturePacket, "winsock:sendto"); // Unhook the function
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	HANDLE HookThread = NULL; // Thread handle for HookControl

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		HookThread = CreateThread(0, 0, HookControl, 0, 0, 0); // Create the thread
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		CloseHandle(HookThread);
		break;
	}
	return TRUE;
}
