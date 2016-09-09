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
PCARD_DATA			g_pCardData = 0;


// Local Functions
void hookInitializeOther(IN	PCARD_DATA	pCardData);


// Initialization of MS Class Mini-driver API function pointers
PFN_CARD_ACQUIRE_CONTEXT	pOrigCardAcquireContext = NULL;


//CardDeleteContext
DWORD WINAPI
pHookCardDeleteContext(
	__inout		PCARD_DATA	pCardData
)
{
	if (logger) {
		logger->TraceInfo("CardDeleteContext");
	}
	return g_pCardData->pfnCardDeleteContext(pCardData);
}


//CardAcquireContext
DWORD WINAPI
pHookCardAcquireContext(
	IN		PCARD_DATA	pCardData,
	__in	DWORD		dwFlags
)
{
	DWORD	dwRet;
	if (logger) {
		logger->TraceInfo("CardAcquireContext");
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}
	
	dwRet = pOrigCardAcquireContext(pCardData, dwFlags);

	g_pCardData = (PCARD_DATA)calloc(1, sizeof(CARD_DATA));
	memcpy((PCARD_DATA)g_pCardData, (PCARD_DATA)pCardData, sizeof(CARD_DATA));
	logger->TraceInfo("g_pCardData->cbAtr: %d", g_pCardData->cbAtr);
	logger->TraceInfo("g_pCardData->dwVersion: %d", g_pCardData->dwVersion);
	logger->TraceInfo("g_pCardData->pfnCardDeleteContext: 0x%p", &(g_pCardData->pfnCardDeleteContext));

	//hookInitializeOther(g_pCardData);
	return dwRet;
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
		logger = LOGGER::CLogger::getInstance(LOGGER::LogLevel_Info, LOG_PATH, "");
		if (logger) { logger->TraceInfo("%s is calling %s", strProcessName.c_str(), DLL_HOOKED); }
		return true;
	}
	return false;
}


//hookInitialize
void hookInitialize() {
	g_hDll = LoadLibrary(DLL_HOOKED_W);

	//GetProcAddress
	pOrigCardAcquireContext = (PFN_CARD_ACQUIRE_CONTEXT)GetProcAddress(g_hDll, "CardAcquireContext");

	//Mhook_SetHook
	Mhook_SetHook((PVOID *)&pOrigCardAcquireContext, pHookCardAcquireContext);
}


//hookInitializeOther
void hookInitializeOther(IN	PCARD_DATA	pCardData) {
	//Mhook_SetHook
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardDeleteContext), pHookCardDeleteContext);
}


//hookFinalize
void hookFinalize() {
	//Mhook_Unhook
	Mhook_Unhook((PVOID*)&pOrigCardAcquireContext);
}


//DllMain
BOOL WINAPI DllMain(
	__in HINSTANCE  hInstance,
	__in DWORD      Reason,
	__in LPVOID     Reserved
)
{
	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		if (shouldHook()) {
			hookInitialize();
		} else {
			return FALSE;
		}
		break;

	case DLL_PROCESS_DETACH:
		hookFinalize();
		break;
	}
	return TRUE;
}