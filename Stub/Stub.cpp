#include "Stub.h"
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

extern "C" __declspec(dllexport) GLOBAL_PARAM g_stcParam = { (PBYTE)(Start) };
fnGetProcAddress pfnGetProcAddress;
fnLoadLibraryA pfnLoadLibraryA;

ULONGLONG GetKernel32Addr()
{
	ULONGLONG dwKernel32Addr = 0;
	_TEB* pPeb = (_TEB*)__readgsqword(0x60);
	PULONGLONG pLdr = (PULONGLONG) * (PULONGLONG)((ULONGLONG)pPeb + 0x18);
	PULONGLONG pInLoadOrderModuleList = (PULONGLONG)((ULONGLONG)pLdr + 0x10);
	PULONGLONG pModuleExe = (PULONGLONG)*pInLoadOrderModuleList;
	PULONGLONG pModuleNtdll = (PULONGLONG)*pModuleExe;
	PULONGLONG pModuleKernel32 = (PULONGLONG)*pModuleNtdll;
	dwKernel32Addr = pModuleKernel32[6];
	return dwKernel32Addr;
}

int mystrcmp(const char* p, const char* q) {
	while (*p == *q && *p != '\0') {
		p++;
		q++;
	}
	return *p - *q;
}

ULONGLONG MyGetProcAddress()
{
	ULONGLONG dwBase = GetKernel32Addr();
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwBase;
	PIMAGE_NT_HEADERS64  pNt = (PIMAGE_NT_HEADERS64)(dwBase + pDos->e_lfanew);
	PIMAGE_DATA_DIRECTORY pExportDir = pNt->OptionalHeader.DataDirectory;
	pExportDir = &(pExportDir[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	DWORD dwOffset = pExportDir->VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dwBase + dwOffset);
	DWORD dwFunCount = pExport->NumberOfFunctions;
	DWORD dwFunNameCount = pExport->NumberOfNames;
	PDWORD pEAT = (PDWORD)(dwBase + pExport->AddressOfFunctions);
	PDWORD pENT = (PDWORD)(dwBase + pExport->AddressOfNames);
	PWORD  pEIT = (PWORD)(dwBase + pExport->AddressOfNameOrdinals);
	const char addre[20] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s','\0' };
	for (int i = 0; i < dwFunNameCount; i++) {
		if (!mystrcmp((char*)pENT[i] + dwBase, addre))
			return dwBase + pEAT[pEIT[i]];
	}
	return 0;
}

void encryptCode()
{
	PBYTE pBase = (PBYTE)((ULONGLONG)g_stcParam.dwImageBase + g_stcParam.lpStartVA);
	BYTE j;
	for (DWORD i = 0; i < g_stcParam.dwCodeSize; i++)
	{
		j = (BYTE)g_stcParam.pass[i % g_stcParam.passlen] + (BYTE)i;
		pBase[i] ^= j;
	}
}

void RecIAT64()
{
	// 1. Get the import table structure pointer
	PIMAGE_IMPORT_DESCRIPTOR pPEImport =
		(PIMAGE_IMPORT_DESCRIPTOR)(g_stcParam.dwImageBase + g_stcParam.importrva);

	// 3. Start repairing IAT
	while (pPEImport->Name)
	{
		DWORD dwModNameRVA = pPEImport->Name;
		char* pModName = (char*)(g_stcParam.dwImageBase + dwModNameRVA);
		HMODULE hMod = pfnLoadLibraryA(pModName);

		PIMAGE_THUNK_DATA64 pIAT = (PIMAGE_THUNK_DATA64)(g_stcParam.dwImageBase + pPEImport->FirstThunk);

		while (pIAT->u1.AddressOfData)
		{
			// Check if function is identified by ordinal or name
			if (IMAGE_SNAP_BY_ORDINAL64(pIAT->u1.Ordinal))
			{
				// Ordinal-based import
				DWORD64 dwFunOrdinal = (pIAT->u1.Ordinal) & 0x7FFFFFFFFFFFFFFF;
				ULONGLONG dwFunAddr = (ULONGLONG)pfnGetProcAddress(hMod, (char*)dwFunOrdinal);
				pIAT->u1.Function = dwFunAddr;
			}
			else
			{
				// Name-based import
				DWORD64 dwFunNameRVA = pIAT->u1.AddressOfData;
				PIMAGE_IMPORT_BY_NAME pstcFunName = (PIMAGE_IMPORT_BY_NAME)(g_stcParam.dwImageBase + dwFunNameRVA);
				ULONGLONG dwFunAddr = (ULONGLONG)pfnGetProcAddress(hMod, pstcFunName->Name);
				pIAT->u1.Function = dwFunAddr;
			}
			pIAT++;
		}
		// Move to the next module
		pPEImport++;
	}
}

void  Start()
{
	pfnGetProcAddress = (fnGetProcAddress)MyGetProcAddress();
	ULONGLONG dwBase = GetKernel32Addr();
	fnVirtualProtect pfnVirtualProtect = (fnVirtualProtect)pfnGetProcAddress((HMODULE)dwBase, "VirtualProtect");
	pfnLoadLibraryA = (fnLoadLibraryA)pfnGetProcAddress((HMODULE)dwBase, "LoadLibraryA");
	fnGetModuleHandleA pfnGetModuleHandleA = (fnGetModuleHandleA)pfnGetProcAddress((HMODULE)dwBase, "GetModuleHandleA");
	HMODULE hUser32 = (HMODULE)pfnLoadLibraryA("user32.dll");
	fnMessageBox pfnMessageBoxA = (fnMessageBox)pfnGetProcAddress(hUser32, "MessageBoxA");
	HMODULE hKernel32 = (HMODULE)pfnGetModuleHandleA("kernel32.dll");
	fnExitProcess pfnExitProcess = (fnExitProcess)pfnGetProcAddress(hKernel32, "ExitProcess");
	fnGetStdHandle pfnGetStdHandle = (fnGetStdHandle)pfnGetProcAddress((HMODULE)dwBase, "GetStdHandle");
	fnReadConsoleA pfnReadConsoleA = (fnReadConsoleA)pfnGetProcAddress((HMODULE)dwBase, "ReadConsoleA");
	fnWriteConsoleA pfnWriteConsoleA = (fnWriteConsoleA)pfnGetProcAddress((HMODULE)dwBase, "WriteConsoleA");


	pfnMessageBoxA(NULL, "请在程序窗口输入密码", "提示", MB_OK);
	HANDLE hConsole1 = pfnGetStdHandle(STD_INPUT_HANDLE);
	HANDLE hConsole2 = pfnGetStdHandle(STD_OUTPUT_HANDLE);
	char inputBuffer[100] = { 0 };
	char Buffer[100] = "请输入密码:";
	DWORD charsRead;
	pfnWriteConsoleA(hConsole2, Buffer, 20, NULL, NULL);
	pfnReadConsoleA(hConsole1, inputBuffer, sizeof(inputBuffer) - 1, &charsRead, NULL);
	memcpy_s(g_stcParam.pass, 30, inputBuffer, 30);


	ULONGLONG dwCodeBase = g_stcParam.dwImageBase + (DWORD)g_stcParam.lpStartVA;
	DWORD dwOldProtect = 0;
	pfnVirtualProtect((LPBYTE)dwCodeBase, g_stcParam.dwCodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	encryptCode();
	pfnVirtualProtect((LPBYTE)dwCodeBase, g_stcParam.dwCodeSize, dwOldProtect, &dwOldProtect);


	ULONGLONG impsecrva = g_stcParam.dwImageBase + (DWORD)g_stcParam.Virrva;
	pfnVirtualProtect((LPBYTE)impsecrva, g_stcParam.Virsize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	RecIAT64();
	pfnVirtualProtect((LPBYTE)impsecrva, g_stcParam.Virsize, dwOldProtect, &dwOldProtect);


	typedef void(*FUN)();
	FUN g_oep = (FUN)(g_stcParam.dwImageBase + g_stcParam.dwOEP);
	g_oep();

	pfnExitProcess(0);
}