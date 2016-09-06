#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include "mhook/mhook-lib/mhook.h"
#include "Logger.h"
#include "inc_cpdk\cardmod.h"


// Global Variables
#define				LOG_PATH		"C:\\Logs\\"
#define				APP_HOOKING		L"C:\\Windows\\system32\\LogonUI.exe"
#define				DLL_HOOKED_W	L"msclmd.dll"
#define				DLL_HOOKED		"msclmd.dll"
LOGGER::CLogger*	logger = NULL;
HMODULE				g_hDll = 0;


//initialization of MS Class Mini-driver API function pointers
PFN_CARD_ACQUIRE_CONTEXT	pOrigCardAcquireContext = NULL;


//CardAcquireContext
DWORD WINAPI
pHookCardAcquireContext(
	IN		PCARD_DATA	pCardData,
	__in	DWORD		dwFlags
)
{
	if (logger) {
		logger->TraceInfo("CardAcquireContext");
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}
	return pOrigCardAcquireContext(pCardData, dwFlags);
}


//////////////////////////////////////////////////////////////////////////////////////
//
//	Private Helper Functions
//
//////////////////////////////////////////////////////////////////////////////////////

//shouldHook
bool shouldHook() {
	wchar_t	wProcessName[MAX_PATH];
	GetModuleFileName(NULL, wProcessName, MAX_PATH);
	std::wstring wsPN(wProcessName);//convert wchar* to wstring
	std::string strProcessName(wsPN.begin(), wsPN.end());
	if (0 == wcscmp(APP_HOOKING, wProcessName)) {
		if (logger) { logger->TraceInfo("%s is hooking onto a %s", strProcessName.c_str(), DLL_HOOKED); }
		return true;
	} else {
		if (logger) { logger->TraceInfo("%s is NOT hooking onto anything", strProcessName.c_str()); }
	}
	return false;
}


//hookInitialize
void hookInitialize() {
	if (shouldHook()) {
		g_hDll = LoadLibrary(DLL_HOOKED_W);

		//GetProcAddress
		pOrigCardAcquireContext = (PFN_CARD_ACQUIRE_CONTEXT)GetProcAddress(g_hDll, "CardAcquireContext");

		//Mhook_SetHook
		Mhook_SetHook((PVOID*)&pOrigCardAcquireContext, pHookCardAcquireContext);
	}
}


//hookFinalize
void hookFinalize() {
	if (shouldHook()) {
		//Mhook_Unhook
		Mhook_Unhook((PVOID*)&pOrigCardAcquireContext);
	}
}


//DllMain
BOOL WINAPI DllMain(
	__in HINSTANCE  hInstance,
	__in DWORD      Reason,
	__in LPVOID     Reserved
)
{
	logger = LOGGER::CLogger::getInstance(LOGGER::LogLevel_Info, LOG_PATH, "");

	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		hookInitialize();
		break;

	case DLL_PROCESS_DETACH:
		hookFinalize();
		break;
	}
	return TRUE;
}