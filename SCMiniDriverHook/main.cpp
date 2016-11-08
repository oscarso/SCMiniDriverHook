#include "stdafx.h"
#include <stdio.h>
#include <mutex>
#include "mhook/mhook-lib/mhook.h"
#include "Logger.h"
#include "inc_cpdk\cardmod.h"


// Global Variables
#define				LOG_PATH		"C:\\Logs\\"
#define				APP_HOOKING		L"C:\\Windows\\system32\\certutil.exe" //Case Sensitive!!!
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
		logger->PrintBuffer(pCardData->pwszCardName, wcslen(pCardData->pwszCardName));
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

	hookInitializeOther(g_pCardData);
	return dwRet;
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
	return g_pCardData->pfnCardDeleteContext(pCardData);
}


//CardCreateContainer
DWORD WINAPI
pHookCardCreateContainer(
	__in	PCARD_DATA	pCardData,
	__in	BYTE		bContainerIndex,
	__in	DWORD		dwFlags,
	__in	DWORD		dwKeySpec,
	__in	DWORD		dwKeySize,
	__in	PBYTE		pbKeyData
)
{
	if (logger) {
		logger->TraceInfo("CardCreateContainer");
	}
	return g_pCardData->pfnCardCreateContainer(pCardData, bContainerIndex, dwFlags, dwKeySpec, dwKeySize, pbKeyData);
}


//CardDeleteContainer
DWORD WINAPI
pHookCardDeleteContainer(
	__in	PCARD_DATA		pCardData,
	__in	BYTE			bContainerIndex,
	__in	DWORD			dwReserved
)
{
	if (logger) {
		logger->TraceInfo("CardDeleteContainer");
	}
	return g_pCardData->pfnCardDeleteContainer(pCardData, bContainerIndex, dwReserved);
}


//CardGetContainerInfo
DWORD WINAPI
pHookCardGetContainerInfo(
	__in	PCARD_DATA		pCardData,
	__in	BYTE			bContainerIndex,
	__in	DWORD			dwFlags,
	__in	PCONTAINER_INFO	pContainerInfo
)
{
	if (logger) {
		logger->TraceInfo("CardGetContainerInfo");
	}
	return g_pCardData->pfnCardGetContainerInfo(pCardData, bContainerIndex, dwFlags, pContainerInfo);
}


//CardGetContainerProperty
DWORD WINAPI
pHookCardGetContainerProperty(
	__in	PCARD_DATA									pCardData,
	__in	BYTE										bContainerIndex,
	__in	LPCWSTR										wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen)	PBYTE	pbData,
	__in	DWORD										cbData,
	__out	PDWORD										pdwDataLen,
	__in	DWORD										dwFlags
)
{
	if (logger) {
		logger->TraceInfo("CardGetContainerProperty");
	}
	return g_pCardData->pfnCardGetContainerProperty(pCardData, bContainerIndex, wszProperty, pbData, cbData, pdwDataLen, dwFlags);
}


//CardSetContainerProperty
DWORD WINAPI
pHookCardSetContainerProperty(
	__in	PCARD_DATA				pCardData,
	__in	BYTE					bContainerIndex,
	__in	LPCWSTR					wszProperty,
	__in_bcount(cbDataLen)	PBYTE	pbData,
	__in	DWORD					cbDataLen,
	__in	DWORD					dwFlags
)
{
	if (logger) {
		logger->TraceInfo("CardSetContainerProperty");
	}
	return g_pCardData->pfnCardSetContainerProperty(pCardData, bContainerIndex, wszProperty, pbData, cbDataLen, dwFlags);
}


//CardAuthenticatePin
DWORD WINAPI
pHookCardAuthenticatePin(
	__in					PCARD_DATA	pCardData,
	__in					LPWSTR		pwszUserId,
	__in_bcount(cbPin)		PBYTE		pbPin,
	__in					DWORD		cbPin,
	__out_opt				PDWORD		pcAttemptsRemaining
)
{
	if (logger) {
		logger->TraceInfo("CardAuthenticatePin");
	}
	return g_pCardData->pfnCardAuthenticatePin(pCardData, pwszUserId, pbPin, cbPin, pcAttemptsRemaining);
}


//CardReadFile
DWORD WINAPI
pHookCardReadFile(
	__in							PCARD_DATA	pCardData,
	__in							LPSTR		pszDirectoryName,
	__in							LPSTR		pszFileName,
	__in							DWORD		dwFlags,
	__deref_out_bcount(*pcbData)	PBYTE*		ppbData,
	__out							PDWORD		pcbData
)
{
	if (logger) {
		logger->TraceInfo("CardReadFile");
	}
	return g_pCardData->pfnCardReadFile(pCardData, pszDirectoryName, pszFileName, dwFlags, ppbData, pcbData);
}


//CardWriteFile
DWORD WINAPI
pHookCardWriteFile(
	__in					PCARD_DATA	pCardData,
	__in					LPSTR		pszDirectoryName,
	__in					LPSTR		pszFileName,
	__in					DWORD		dwFlags,
	__in_bcount(cbData)		PBYTE		pbData,
	__in					DWORD		cbData
)
{
	if (logger) {
		logger->TraceInfo("CardWriteFile");
	}
	return g_pCardData->pfnCardWriteFile(pCardData, pszDirectoryName, pszFileName, dwFlags, pbData, cbData);
}


//CardGetProperty
DWORD WINAPI
pHookCardGetProperty(
	__in	PCARD_DATA									pCardData,
	__in	LPCWSTR										wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen)	PBYTE	pbData,
	__in	DWORD										cbData,
	__out	PDWORD										pdwDataLen,
	__in	DWORD										dwFlags
)
{
	if (logger) {
		logger->TraceInfo("CardGetProperty");
	}
	return g_pCardData->pfnCardGetProperty(pCardData, wszProperty, pbData, cbData, pdwDataLen, dwFlags);
}


//CardSetProperty
DWORD WINAPI
pHookCardSetProperty(
	__in	PCARD_DATA				pCardData,
	__in	LPCWSTR					wszProperty,
	__in_bcount(cbDataLen)	PBYTE	pbData,
	__in	DWORD					cbDataLen,
	__in	DWORD					dwFlags
)
{
	if (logger) {
		logger->TraceInfo("CardSetProperty");
	}
	return g_pCardData->pfnCardSetProperty(pCardData, wszProperty, pbData, cbDataLen, dwFlags);
}


//CardQueryFreeSpace
DWORD WINAPI
pHookCardQueryFreeSpace(
	__in	PCARD_DATA				pCardData,
	__in	DWORD					dwFlags,
	__in	PCARD_FREE_SPACE_INFO	pCardFreeSpaceInfo
)
{
	if (logger) {
		logger->TraceInfo("CardQueryFreeSpace");
	}
	return g_pCardData->pfnCardQueryFreeSpace(pCardData, dwFlags, pCardFreeSpaceInfo);
}


//CardQueryCapabilities
DWORD WINAPI
pHookCardQueryCapabilities(
	__in	PCARD_DATA			pCardData,
	__in	PCARD_CAPABILITIES	pCardCapabilities
)
{
	if (logger) {
		logger->TraceInfo("CardQueryCapabilities");
	}
	return g_pCardData->pfnCardQueryCapabilities(pCardData, pCardCapabilities);
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
	//OutputDebugString(L"SCMiniDriverHook: shouldHook - ProcessName:");
	//OutputDebugString(wProcessName);
	if (logger) { logger->TraceInfo("ProcessName is: %s", strProcessName.c_str()); }
	if (0 == wcscmp(APP_HOOKING, wProcessName)) {
		logger = LOGGER::CLogger::getInstance(LOGGER::LogLevel_Info, LOG_PATH, "");
		if (logger) { logger->TraceInfo("%s is calling %s", strProcessName.c_str(), DLL_HOOKED); }
		//OutputDebugString(L"SCMiniDriverHook: shouldHook returns TRUE");
		return true;
	}
	return false;
}


//hookInitialize
void hookInitialize() {
	//OutputDebugString(L"SCMiniDriverHook: hookInitialize");
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
#if 0
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardAuthenticatePin), pHookCardAuthenticatePin);

	Mhook_SetHook((PVOID *)&(pCardData->pfnCardReadFile), pHookCardReadFile);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardWriteFile), pHookCardWriteFile);

	Mhook_SetHook((PVOID *)&(pCardData->pfnCardCreateContainer), pHookCardCreateContainer);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardDeleteContainer), pHookCardDeleteContainer);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardGetContainerInfo), pHookCardGetContainerInfo);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardGetContainerProperty), pHookCardGetContainerProperty);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardSetContainerProperty), pHookCardSetContainerProperty);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardGetProperty), pHookCardGetProperty);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardSetProperty), pHookCardSetProperty);

	Mhook_SetHook((PVOID *)&(pCardData->pfnCardQueryFreeSpace), pHookCardQueryFreeSpace);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardQueryCapabilities), pHookCardQueryCapabilities);
#endif
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
		//OutputDebugString(L"SCMiniDriverHook: DllMain");
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