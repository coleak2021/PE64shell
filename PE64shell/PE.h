#include <Windows.h>
#include<afx.h>
#include <Psapi.h>
#include<shlwapi.h>
#include<iostream>
#include <afx.h>
#include <Psapi.h>
#pragma comment(lib,"psapi.lib")
#include "../Stub/Stub.h"

class CPE {
public:

    //函数声明
    CPE();
    BOOL Pack(CString strPath, const char* pass);
    void encryptCode(PGLOBAL_PARAM g_stcParam);
    BOOL InitPE(CString strPath);
    DWORD RVA2OffSet(DWORD dwRVA, PIMAGE_NT_HEADERS64 pNt);
    ULONGLONG AddSection(LPBYTE pBuffer, DWORD dwSize, PCHAR pszSectionName);
    void FixReloc(PBYTE pBuffer, DWORD newRVA);
    void SetNewOEP(DWORD newOEP);
    void ClearRandBase();
    void ClearBundleImport();
    DWORD GetSectionData(PBYTE lpImage, PBYTE& lpBuffer, DWORD& dwCodeBaseRVA);
    DWORD Gettextsize(PBYTE lpImage);
    ULONGLONG GetImportTableAddress(LPVOID lpFileBase);
    void hideimporttable(int& Size, int& VirtualAddress, int& viradd, int& virsize);
    BOOL addimport(char* newtable, DWORD dwSize);
    DWORD findtablerva(DWORD size);

    //变量声明
    ULONGLONG m_dwImageBase;
    DWORD m_dwOEP; //old oep
    DWORD m_dwCodeBase;//.text rva
    DWORD m_dwCodeSize;//.text size
    DWORD m_dwNewSectionRVA; //packer rva
    DWORD m_dwNewOEP; //packer 中start 段rva
    //read file from computer
    CFile m_objFile;
    BYTE* m_pFileBase; //readbase
    DWORD m_dwFileSize;
    DWORD m_dwFileAlign;
    DWORD m_dwMemAlign;
    PIMAGE_NT_HEADERS64 m_pNT;
    PIMAGE_SECTION_HEADER m_pLastSection;
    ULONGLONG ImportTable;
    DWORD  Importsize;
};