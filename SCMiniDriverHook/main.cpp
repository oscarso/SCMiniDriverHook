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
	DWORD	dwRet = SCARD_S_SUCCESS;
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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####     CardDeleteContext     #####");
		logger->TraceInfo("#####################################");
	}
	dwRet = g_pCardData->pfnCardDeleteContext(pCardData);
	return dwRet;
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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardCreateContainer    #####");
		logger->TraceInfo("#####################################");
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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardDeleteContainer    #####");
		logger->TraceInfo("#####################################");
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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardGetContainerInfo    #####");
		logger->TraceInfo("######################################");
		logger->TraceInfo("IN bContainerIndex: %d", bContainerIndex);
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####   CardGetContainerProperty   #####");
		logger->TraceInfo("########################################");
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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####   CardSetContainerProperty   #####");
		logger->TraceInfo("########################################");
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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardAuthenticatePin    #####");
		logger->TraceInfo("#####################################");
		char userID[MAX_PATH] = { 0 };
		wcstombs(userID, pwszUserId, wcslen(pwszUserId));
		logger->TraceInfo("IN pwszUserId: %s", userID);
		logger->TraceInfo("IN pbPin");
		logger->PrintBuffer(pbPin, cbPin);
		logger->TraceInfo("IN pcAttemptsRemaining: %p", pcAttemptsRemaining);
	}
	dwRet = g_pCardData->pfnCardAuthenticatePin(pCardData, pwszUserId, pbPin, cbPin, pcAttemptsRemaining);

	return dwRet;
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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardReadFile    #####");
		logger->TraceInfo("##############################");
		logger->TraceInfo("IN pszDirectoryName: %s", pszDirectoryName);
		logger->TraceInfo("IN pszFileName: %s", pszFileName);
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}
	dwRet = g_pCardData->pfnCardReadFile(pCardData, pszDirectoryName, pszFileName, dwFlags, ppbData, pcbData);

	if (logger) {
		logger->TraceInfo("OUT: *pcbData = %d", *pcbData);
		logger->TraceInfo("OUT: *ppbData");
		logger->PrintBuffer(*ppbData, *pcbData);
		logger->TraceInfo("CardReadFile returns %x", dwRet);
	}
	return dwRet;
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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardWriteFile    #####");
		logger->TraceInfo("###############################");
		logger->TraceInfo("IN pszDirectoryName: %s", pszDirectoryName);
		logger->TraceInfo("IN pszFileName: %s", pszFileName);
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
		logger->TraceInfo("IN pbData:");
		logger->PrintBuffer(pbData, cbData);
	}
	dwRet = g_pCardData->pfnCardWriteFile(pCardData, pszDirectoryName, pszFileName, dwFlags, pbData, cbData);

	return dwRet;
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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####   CardGetProperty   #####");
		logger->TraceInfo("###############################");
		char prop[MAX_PATH] = { 0 };
		wcstombs(prop, wszProperty, wcslen(wszProperty));
		logger->TraceInfo("IN wszProperty: %s", prop);
		logger->TraceInfo("IN cbData: %d", cbData);
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}
	dwRet = g_pCardData->pfnCardGetProperty(pCardData, wszProperty, pbData, cbData, pdwDataLen, dwFlags);

	if (logger) {
		logger->TraceInfo("OUT: pbData:");
		logger->PrintBuffer(pbData, cbData);
		logger->TraceInfo("OUT: *pdwDataLen: %d", *pdwDataLen);
		logger->TraceInfo("CardGetProperty returns %x", dwRet);
	}
	return dwRet;
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
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####   CardSetProperty   #####");
		logger->TraceInfo("###############################");
		char prop[MAX_PATH] = { 0 };
		wcstombs(prop, wszProperty, wcslen(wszProperty));
		logger->TraceInfo("IN wszProperty: %s", prop);
		logger->TraceInfo("IN cbDataLen: %d", cbDataLen);
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}
	dwRet = g_pCardData->pfnCardSetProperty(pCardData, wszProperty, pbData, cbDataLen, dwFlags);
	return dwRet;
}


//CardQueryFreeSpace
DWORD WINAPI
pHookCardQueryFreeSpace(
	__in	PCARD_DATA				pCardData,
	__in	DWORD					dwFlags,
	__in	PCARD_FREE_SPACE_INFO	pCardFreeSpaceInfo
)
{
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardQueryFreeSpace    #####");
		logger->TraceInfo("####################################");
		logger->TraceInfo("IN dwFlags: %x", dwFlags);
	}
	dwRet = g_pCardData->pfnCardQueryFreeSpace(pCardData, dwFlags, pCardFreeSpaceInfo);

	if (logger) {
		logger->TraceInfo("OUT dwVersion: %x", pCardFreeSpaceInfo->dwVersion);
		logger->TraceInfo("OUT dwBytesAvailable: %x", pCardFreeSpaceInfo->dwBytesAvailable);
		logger->TraceInfo("OUT dwKeyContainersAvailable: %x", pCardFreeSpaceInfo->dwKeyContainersAvailable);
		logger->TraceInfo("OUT dwMaxKeyContainers: %x", pCardFreeSpaceInfo->dwMaxKeyContainers);
	}
	return dwRet;
}


//CardQueryCapabilities
DWORD WINAPI
pHookCardQueryCapabilities(
	__in	PCARD_DATA			pCardData,
	__in	PCARD_CAPABILITIES	pCardCapabilities
)
{
	DWORD	dwRet = SCARD_S_SUCCESS;
	if (logger) {
		logger->TraceInfo("\n");
		logger->TraceInfo("#####    CardQueryCapabilities    #####");
		logger->TraceInfo("#######################################");
	}
	dwRet = g_pCardData->pfnCardQueryCapabilities(pCardData, pCardCapabilities);

	if (logger) {
		logger->TraceInfo("OUT: dwVersion: %x", pCardCapabilities->dwVersion);
		logger->TraceInfo("OUT: fCertCompress: %s", pCardCapabilities->fCertificateCompression ? "TRUE" : "FALSE");
		logger->TraceInfo("OUT: fKeyGen: %s", pCardCapabilities->fKeyGen ? "TRUE" : "FALSE");
	}
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
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardReadFile), pHookCardReadFile);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardWriteFile), pHookCardWriteFile);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardGetProperty), pHookCardGetProperty);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardSetProperty), pHookCardSetProperty);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardQueryFreeSpace), pHookCardQueryFreeSpace);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardQueryCapabilities), pHookCardQueryCapabilities);

#if 0
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardAuthenticatePin), pHookCardAuthenticatePin);

	Mhook_SetHook((PVOID *)&(pCardData->pfnCardDeleteContext), pHookCardDeleteContext);

	Mhook_SetHook((PVOID *)&(pCardData->pfnCardCreateContainer), pHookCardCreateContainer);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardDeleteContainer), pHookCardDeleteContainer);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardGetContainerInfo), pHookCardGetContainerInfo);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardGetContainerProperty), pHookCardGetContainerProperty);
	Mhook_SetHook((PVOID *)&(pCardData->pfnCardSetContainerProperty), pHookCardSetContainerProperty);
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