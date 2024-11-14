## 前记

- 开源的关于PE压缩和加密壳几乎都是32位，于是学习写一个64位的壳供参考，其原理差别不大

- 学写PE壳是熟悉PE结构很好的方式




## x64壳

代码分布：

stub：外壳，负责解密.text，解析修复IAT，跳转到原来的OEP

PE64shell：将stub的.text节和导入表打包尾加到待加壳的PE并修改一系列文件头信息

效果展示：

![show](pic/show.gif)





## 后记

**变量存储**

```c++
#include<string>
#include<iostream>
using namespace std;
static int C = 6;//.data节
int c=5;//.data节
int main() {
	int a = 10;//ebp-8
	int n = ++a;//ebp-c
	c = n;
	cout << n<<endl<< c << endl;
	cout << &n << endl <<&a<< endl<<&c<< endl;
	cout << C << endl << &C;
}
```

> 11
> 11
> 000000A4DBF7FBB0
> 000000A4DBF7FBB4
> 00007FF7064FBC80
> 6
> 00007FF7064FBC84



**rdata、idata、data**

权限：

- `.rdata`：只读，不可修改。
- `.idata`：通常为读
- `.data`：读写，允许修改全局和静态变量。

存储内容：

- `.rdata`：存储const修饰的变量
- `.idata`：导入函数的代码段，存放外部函数地址
- `.data`：存储可变的全局和static变量

```
//把数据段融入代码段
#pragma comment(linker,"/merge:.data=.text")
//把只读数据段融入代码段
#pragma comment(linker,"/merge:.rdata=.text")
//设置代码段为可读可写可执行
#pragma comment(linker,"/section:.text,RWE")
```



**windbg**

```c++
0:005> dt _PEB
ntdll!_PEB
   +0x000 InheritedAddressSpace : UChar
   +0x001 ReadImageFileExecOptions : UChar
   +0x002 BeingDebugged    : UChar
   +0x003 BitField         : UChar
   +0x003 ImageUsesLargePages : Pos 0, 1 Bit
   +0x003 IsProtectedProcess : Pos 1, 1 Bit
   +0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
   +0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
   +0x003 IsPackagedProcess : Pos 4, 1 Bit
   +0x003 IsAppContainer   : Pos 5, 1 Bit
   +0x003 IsProtectedProcessLight : Pos 6, 1 Bit
   +0x003 IsLongPathAwareProcess : Pos 7, 1 Bit
   +0x004 Padding0         : [4] UChar
   +0x008 Mutant           : Ptr64 Void
   +0x010 ImageBaseAddress : Ptr64 Void
   +0x018 Ldr              : Ptr64 _PEB_LDR_DATA

0:005> !peb
PEB at 00000046b97eb000

0:005> dt _PEB_LDR_DATA
ntdll!_PEB_LDR_DATA
   +0x000 Length           : Uint4B
   +0x004 Initialized      : UChar
   +0x008 SsHandle         : Ptr64 Void
   +0x010 InLoadOrderModuleList : _LIST_ENTRY
   +0x020 InMemoryOrderModuleList : _LIST_ENTRY
   +0x030 InInitializationOrderModuleList : _LIST_ENTRY
   +0x040 EntryInProgress  : Ptr64 Void
   +0x048 ShutdownInProgress : UChar
   +0x050 ShutdownThreadId : Ptr64 Void

0:005> dt nt!_PEB Ldr Ldr. 00000046b97eb018
ntdll!_PEB
   +0x018 Ldr  : 0x00000224`f6bb0000 _PEB_LDR_DATA
      +0x000 Length : 0
      +0x004 Initialized : 0 ''
      +0x008 SsHandle : 0x010040fd`e9f11c7d Void
      +0x010 InLoadOrderModuleList : _LIST_ENTRY [ 0x00000002`ffeeffee - 0x00000224`f6bb0120 ]
      +0x020 InMemoryOrderModuleList : _LIST_ENTRY [ 0x00000224`f6bb0120 - 0x00000224`f6bb0000 ]
      +0x030 InInitializationOrderModuleList : _LIST_ENTRY [ 0x00000224`f6bb0000 - 0x00000000`000000ff ]
      +0x040 EntryInProgress : 0x00000224`f6bb0740 Void
      +0x048 ShutdownInProgress : 0 ''
      +0x050 ShutdownThreadId : 0x00000001`000000a5 Void
      
0:005> dt _LDR_DATA_TABLE_ENTRY
ntdll!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY
   +0x010 InMemoryOrderLinks : _LIST_ENTRY
   +0x020 InInitializationOrderLinks : _LIST_ENTRY
   +0x030 DllBase          : Ptr64 Void
   +0x038 EntryPoint       : Ptr64 Void
   +0x040 SizeOfImage      : Uint4B
   +0x048 FullDllName      : _UNICODE_STRING
   +0x058 BaseDllName      : _UNICODE_STRING
```



**getKernel32Addr**

```c++
#include<windows.h>
#include<iostream>

ULONGLONG GetKernel32Addr()
{
	ULONGLONG dwKernel32Addr = 0;
	// 获取PEB的地址
	_TEB* pPeb =(_TEB*) __readgsqword(0x60);
	// 获取PEB_LDR_DATA结构的地址
	PULONGLONG pLdr = (PULONGLONG) * (PULONGLONG)((ULONGLONG)pPeb + 0x18);
	//模块初始化链表的头指针InInitializationOrderModuleList
	PULONGLONG pInLoadOrderModuleList = (PULONGLONG)((ULONGLONG)pLdr + 0x10);
	// 获取链表中第一个模块信息，exe模块
	PULONGLONG pModuleExe = (PULONGLONG)*pInLoadOrderModuleList;
	// 获取链表中第二个模块信息，ntdll模块
	PULONGLONG pModuleNtdll = (PULONGLONG)*pModuleExe;
	// 获取链表中第三个模块信息，Kernel32模块
	PULONGLONG pModuleKernel32 = (PULONGLONG)*pModuleNtdll;
	// 获取kernel32基址
	dwKernel32Addr = pModuleKernel32[6];
	return dwKernel32Addr;
}

ULONGLONG MyGetProcAddress()
{
	ULONGLONG dwBase = GetKernel32Addr();
	// 1. 获取DOS头
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dwBase;
	// 2. 获取NT头
	PIMAGE_NT_HEADERS64  pNt = (PIMAGE_NT_HEADERS64)(dwBase + pDos->e_lfanew);
	// 3. 获取数据目录表
	PIMAGE_DATA_DIRECTORY pExportDir = pNt->OptionalHeader.DataDirectory;
	pExportDir = &(pExportDir[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	DWORD dwOffset = pExportDir->VirtualAddress;
	// 4. 获取导出表信息结构
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(dwBase + dwOffset);
	DWORD dwFunCount = pExport->NumberOfFunctions;
	DWORD dwFunNameCount = pExport->NumberOfNames;
	// Get Export Address Table
	PDWORD pEAT = (PDWORD)(dwBase + pExport->AddressOfFunctions);
	// Get Export Name Table
	PDWORD pENT = (PDWORD)(dwBase + pExport->AddressOfNames);
	// Get Export Index Table
	PWORD  pEIT = (PWORD)(dwBase + pExport->AddressOfNameOrdinals);

	for (int i = 0; i < dwFunNameCount; i++) {
		if (!strcmp((char*)pENT[i]+ dwBase, "GetProcAddress"))
			return dwBase + pEAT[pEIT[i]];
	}
	return 0;
}
int main()
{
	std::cout << GetProcAddress(GetModuleHandleA("Kernel32"), "GetProcAddress") << std::endl;
	std::cout <<std::hex<< MyGetProcAddress()<<std::endl;
	system("pause");
	return 0;
}
```

> `0x30 / sizeof(ULONGLONG)` 的计算是为了将字节偏移量转换为元素偏移量
>
> `0x30` 是一个以字节为单位的偏移量，表示我们希望跳过的内存区域的大小（在这个例子中是 48 字节）
>
> `sizeof(ULONGLONG)` 是 `ULONGLONG` 类型的大小（在大多数系统上是 8 字节）
>
> 0x30 / sizeof(ULONGLONG) 就是 48 / 8 = 6



**#include "lib.h"+#pragma comment(lib,"lib.lib")/loadlibrarya+getproaddress**

- #pragma comment(lib, "lib.lib")

编译器在链接阶段将 `lib.lib` 添加到项目中。它是在编译时静态确定的。可以直接调用库中的函数，而不需要在运行时手动加载库。仅链接而不使用的时候不会触发dllmain，使用时会先触发dllmain

- loadlibrarya

程序运行时动态加载 DLL并触发dllmain



**zstd压缩**

```c++
#include <windows.h>
#include<iostream>
#include "zstd.h"

#pragma comment(lib,"D:\\c_project\\libzstd_static.lib")

int compre(PVOID input, int dwFileSize, PVOID output);
int decompre(PVOID input, int dwFileSize, PVOID output);
```

```c++
#include "zstd.h"

void mymemcpy_s(char* cc1, int s1, char* cc2)
{
    for (int i = 0; i < s1; i++)
         *cc1++= *cc2++;

}
int compre(PVOID input, int dwFileSize, PVOID output) {
    // 计算压缩后的最大缓冲区大小
    size_t compressed_size_bound = ZSTD_compressBound(dwFileSize);
    char* compressed_data = new char[compressed_size_bound];

    // 压缩数据
    size_t compressed_size = ZSTD_compress(compressed_data, compressed_size_bound, input, dwFileSize, 1);
    mymemcpy_s((char*)output, compressed_size, compressed_data);
    delete[] compressed_data;
    return compressed_size;
}

int decompre(PVOID input, int dwFileSize, PVOID output) {
    // 先计算解压后所需的最大缓冲区大小
    unsigned long long decompressed_size = ZSTD_getFrameContentSize(input, dwFileSize);

    // 分配解压后的数据缓冲区
    char* decompressed_data = new char[decompressed_size];

    // 解压数据
    size_t result = ZSTD_decompress(decompressed_data, decompressed_size, input, dwFileSize);
    if (ZSTD_isError(result)) {
        delete[] decompressed_data;
        return 1;
    }
    mymemcpy_s((char*)output, decompressed_size, decompressed_data);
    delete[] decompressed_data;
    return 0;
}
```



**DllCharacteristics**

```
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x0040)
DLL 支持重定位，可以加载到随机基址。影响 PE 文件随机基址。

IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (0x0080)
强制进行代码完整性检查，确保 DLL 的完整性和安全性。

IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x0100)
与 NX (No-Execute) 兼容，防止在代码段之外的内存区域执行代码，提高安全性。

IMAGE_DLLCHARACTERISTICS_NO_ISOLATION (0x0200)
支持隔离，但此映像不需要隔离环境的保护。

IMAGE_DLLCHARACTERISTICS_NO_SEH (0x0400)
禁用结构化异常处理 (SEH)，该映像中不能包含任何 SEH 处理程序。

IMAGE_DLLCHARACTERISTICS_NO_BIND (0x0800)
指示不绑定此映像到特定 DLL 地址，使其加载更灵活。

0x1000 (Reserved)
保留项。

IMAGE_DLLCHARACTERISTICS_WDM_DRIVER (0x2000)
指示映像是一个使用 Windows 驱动程序模型 (WDM) 的驱动程序。

0x4000 (Reserved)
保留项。

IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE (0x8000)
映像支持终端服务器环境，具有终端服务器感知。
```



**x64/x86**

pe64也就`ImageBase` 、`VA`如`IAT`和`OFT`等、堆栈大小等是ULONGLONG，其他和pe32基本保持一致



## reference

```
https://blog.schnee.moe/posts/SimpleDpack/
https://www.cnblogs.com/z5onk0/p/17287215.html
```

