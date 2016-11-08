#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include "mhook/mhook-lib/mhook.h"
#include "Logger.h"
#include "inc_cpdk\cardmod.h"


// Global Variables
#define				LOG_PATH		"C:\\Logs\\"
#define				APP_HOOKING		L"C:\\Windows\\system32\\certutil.exe"
#define				DLL_HOOKED_W	L"msclmd.dll"
#define				DLL_HOOKED		"msclmd.dll"
LOGGER::CLogger*	logger = NULL;
HMODULE				g_hDll = 0;
PCARD_DATA			g_pCardData = 0;

// Local Functions
void hookInitializeOther(IN	PCARD_DATA	pCardData);


// Initialization of MS Class Mini-driver API function pointers
PFN_CARD_ACQUIRE_CONTEXT	pOrigCardAcquireContext = NULL;


BOOL isHooked() {
	return (
				g_hDll != 0
				||
				pOrigCardAcquireContext != NULL
			);
}


//CardDeleteContext
DWORD WINAPI
pHookCardDeleteContext(
	__inout		PCARD_DATA	pCardData
)
{
	if (logger) {
		logger->TraceInfo("CardDeleteContext");
	}
	return 0;// g_pCardData->pfnCardDeleteContext(pCardData);
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
		logger->TraceInfo("IN pCardData->dwVersion: %d", pCardData->dwVersion);
		logger->TraceInfo("IN pCardData->pbAtr:");
		logger->PrintBuffer(pCardData->pbAtr, pCardData->cbAtr);
		logger->TraceInfo("IN pCardData->pwszCardName:");
		logger->PrintBuffer(pCardData->pwszCardName, lstrlen(pCardData->pwszCardName));
		logger->TraceInfo("IN pCardData->pfnCspAlloc: %p", &(pCardData->pfnCspAlloc));
		logger->TraceInfo("IN pCardData->pfnCspReAlloc: %p", &(pCardData->pfnCspReAlloc));
		logger->TraceInfo("IN pCardData->pfnCspFree: %p", &(pCardData->pfnCspFree));
		logger->TraceInfo("IN pCardData->pfnCspCacheAddFile: %p", &(pCardData->pfnCspCacheAddFile));
		logger->TraceInfo("IN pCardData->pfnCspCacheLookupFile: %p", &(pCardData->pfnCspCacheLookupFile));
		logger->TraceInfo("IN pCardData->pfnCspCacheDeleteFile: %p", &(pCardData->pfnCspCacheDeleteFile));
		logger->TraceInfo("IN pCardData->pvCacheContext: %x", pCardData->pvCacheContext);
		logger->TraceInfo("IN pCardData->pfnCspPadData: %p", &(pCardData->pfnCspPadData));
		logger->TraceInfo("IN pCardData->hSCardCtx: %x", pCardData->hSCardCtx);
		logger->TraceInfo("IN pCardData->hScard: %x", pCardData->hScard);
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
	OutputDebugString(L"SCMiniDriverHook: shouldHook - ProcessName:");
	OutputDebugString(wProcessName);
	if (logger) { logger->TraceInfo("ProcessName is: %s", strProcessName.c_str()); }
	if (0 == wcscmp(APP_HOOKING, wProcessName)) {
		logger = LOGGER::CLogger::getInstance(LOGGER::LogLevel_Info, LOG_PATH, "");
		if (logger) { logger->TraceInfo("%s is calling %s", strProcessName.c_str(), DLL_HOOKED); }
		OutputDebugString(L"SCMiniDriverHook: shouldHook returns TRUE");
		return true;
	}
	return false;
}


//hookInitialize
void hookInitialize() {
	OutputDebugString(L"SCMiniDriverHook: hookInitialize");
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
		OutputDebugString(L"SCMiniDriverHook: DllMain");
		if (shouldHook()) {
			hookInitialize();
		} else {
			return FALSE;
		}
		break;

	case DLL_PROCESS_DETACH:
		if (isHooked()) {
			hookFinalize();
		}
		break;
	}
	return TRUE;
}