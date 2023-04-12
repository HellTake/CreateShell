#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>
#include <PEheaders.h>
#define __NO_STACK_CHECK__
#define PE_SIGNA 0x5a4d // "PE"
#define MZ_SIGNA 0x4550 // "MZ"
#define MAGIC 0x10b // 32位程序
#define MACHINE 0x014c //32位机器架构
#define debug 0
#define KEY 50
#define Image a
//unpackcode(ImageBase,SizeOfHeaders,EncryptSize,section_count,section_point,section_end,OSectionSize,TlsTable,IatTable,TlsSize,IatSize);
unsigned char callunpack[] =
{
    0x60,                                   //pushad
    0x68,0x00,0x00,0x00,0x00,               //push oep
    0x68,0x00,0x00,0x00,0x00,               //push IatSize
    0x68,0x00,0x00,0x00,0x00,               //push TlsSize
    0x68,0x00,0x00,0x00,0x00,               //push IatTable
    0x68,0x00,0x00,0x00,0x00,               //push TlsTable
    0x68,0x00,0x00,0x00,0x00,               //push OSectionSize
    0x68,0x00,0x00,0x00,0x00,               //push section_end
    0x68,0x00,0x00,0x00,0x00,               //push section_point
    0x68,0x00,0x00,0x00,0x00,               //push section_count
    0x68,0x00,0x00,0x00,0x00,               //push EncryptSize
    0x68,0x00,0x00,0x00,0x00,               //push SizeOfHeaders
    0x68,0x00,0x00,0x00,0x00,               //push ImageBase
    0xE8,0x06,0x00,0x00,0x00,               //call unpackcode
    0x61,                                   //popad
    0xE9,0x00,0x00,0x00,0x00                //jmp OEP
};
class File_Control
{
public:
    //文件变量
    int FileSize = 0;         // 记录文件大小
    char FileName[100];		  // 文件名
    int *StrBuffer=0;		 //文件指针

    //PE指针
    IMAGE_DOS_HEADER* dos_header = 0; //DOS头结构体指针
    IMAGE_NT_HEADERS* nt_headers = 0; //NT头结构体指针
    IMAGE_OPTIONAL_HEADER32* optional_headers = 0; //可选头结构体指针
    IMAGE_SECTION_HEADER* section_headers = 0; //节表结构体指针
    //关键属性
    int section_count = 0;              //节数量
    DWORD OEP = 0;                // OEP地址
    int SizeOfHeaders = 0;              //PE文件头大小
    int SizeOfImage = 0;                //文件在内存中的大小
    int ImageBase = 0;                  //内存基址
    int EncryptSize = 0;                //加密内容大小
    int OSectionSize = 0;               //多余段大小
    IMAGE_SECTION_HEADER* section_point = 0;//节表地址
    void* section_end = 0;                  //程序结尾
    //数据目录指针
    _IMAGE_TLS_DIRECTORY32* TlsTable = 0;
    _IMAGE_IMPORT_DESCRIPTOR* IatTable = 0;
    //数据目录大小
    int IatSize = 0;
    int TlsSize = 0 ;
    //方法
    void init(const char* Name);                   //初始化
    void relocat();                                 //重定位
    void output_error(const TCHAR* error_message); //报错输出
    void read_file();                              //读取文件
    void create_file(void *Encrypt,int Size);                             //写入文件
    void* encrypt(unsigned char* text,int size);           //壳加密算法
    void pack();                                    //加壳
    DWORD RvaToFoa(DWORD dwRva);                    //rva转foa
    void unpackcode(int ImageBase,int SizeOfHeaders,int EncryptSize,int section_count,IMAGE_SECTION_HEADER* section_point,void* section_end,int OSectionSize,_IMAGE_TLS_DIRECTORY32* TlsTable,_IMAGE_IMPORT_DESCRIPTOR* IatTable,int TlsSize,int IatSize,int OEP);
    int FileAlignment (int X);
    int MemoryAlignment (int X);
};
int File_Control::MemoryAlignment(int X)
{
    return (X + NewOptionHeader.SectionAlignment-1)/NewOptionHeader.SectionAlignment*NewOptionHeader.SectionAlignment;
}
int File_Control::FileAlignment(int X)
{
    return (X + NewOptionHeader.FileAlignment-1)/NewOptionHeader.FileAlignment*NewOptionHeader.FileAlignment;
}
void File_Control::unpackcode(int ImageBase,int pack1start,int EncryptSize,int section_count,IMAGE_SECTION_HEADER* section_point,void* section_end,int OSectionSize,_IMAGE_TLS_DIRECTORY32* TlsTable,_IMAGE_IMPORT_DESCRIPTOR* IatTable,int TlsSize,int IatSize,int OEP)
{
    //ImageBase,SizeOfHeaders,EncryptSize,section_count,section_point,section_end,OSectionSize,TlsSize,TlsTable,IatSize,IatTable
    //获取需要的函数地址
    typedef FARPROC(WINAPI* MyGetProcAddress)(HMODULE,LPCSTR);
    typedef HMODULE(WINAPI* MyLoadLibrary)(LPCSTR);
    typedef BOOL(WINAPI* VirtualProtectPtr)(LPVOID, SIZE_T, DWORD, PDWORD);
    typedef HMODULE(WINAPI* pGetModuleHandleA_ptr)(LPCSTR lpModuleName);
    typedef void* (*memcpy_ptr)(void*, const void*, size_t);
    typedef void* (*malloc_ptr)(size_t);
    typedef void (*FreeFunc)(void*);
    typedef void (*memset_ptr)(void*,int,size_t);

    PPEB PEB = 0;
    __asm__("movl %%fs:0x30, %0" : "=r" (PEB));
    //获取loadlibrary和getprocaddress函数地址
    MyLoadLibrary pLoadLibrary = 0;
    MyGetProcAddress pGetProcAddress =0;
    PLIST_ENTRY pListEntry = PEB->Ldr->InMemoryOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    pListEntry = pEntry->InMemoryOrderLinks.Flink;
    pEntry = CONTAINING_RECORD(pListEntry->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    _IMAGE_NT_HEADERS* pNT = (_IMAGE_NT_HEADERS*)(pEntry -> DllBase + *((unsigned char*)pEntry -> DllBase + 0x3C));
    _IMAGE_EXPORT_DIRECTORY* pExportDir = (_IMAGE_EXPORT_DIRECTORY*)(pEntry -> DllBase + pNT->OptionalHeader.DataDirectory[0].VirtualAddress);
    DWORD* pFunctions = (DWORD*)(pEntry->DllBase + pExportDir->AddressOfFunctions);
    DWORD* pNames = (DWORD*)(pEntry->DllBase + pExportDir->AddressOfNames);
    WORD* pOrdinals = (WORD*)(pEntry->DllBase + pExportDir->AddressOfNameOrdinals);
    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++)//for(n): strcmp(pFunctionName,"LoadLibrary")...
    {
        char* pFunctionName = (char*)(pEntry->DllBase + pNames[i]);
        int cmp_result1 = 0;
        int cmp_result2 = 0;
        __asm__(
            "cmpb $'L', (%1);"
            "jne 2f;"
            "cmpb $'o', 0x1(%1);"
            "jne 2f;"
            "cmpb $'a', 0x2(%1);"
            "jne 2f;"
            "cmpb $'d', 0x3(%1);"
            "jne 2f;"
            "cmpb $'L', 0x4(%1);"
            "jne 2f;"
            "cmpb $'i', 0x5(%1);"
            "jne 2f;"
            "cmpb $'b', 0x6(%1);"
            "jne 2f;"
            "cmpb $'r', 0x7(%1);"
            "jne 2f;"
            "cmpb $'a', 0x8(%1);"
            "jne 2f;"
            "cmpb $'r', 0x9(%1);"
            "jne 2f;"
            "cmpb $'y', 0xa(%1);"
            "je 3f;"
            "2:"
            "movl $0, %0;"
            "jmp 4f;"
            "3:"
            "movl $1, %0;"
            "4:"
            :"=r"(cmp_result1)
            :"S"(pFunctionName)
    );
    __asm__(
			"cmpb $'G', (%1);"
            "jne 5f;"
            "cmpb $'e', 0x1(%1);"
            "jne 5f;"
            "cmpb $'t', 0x2(%1);"
            "jne 5f;"
            "cmpb $'P', 0x3(%1);"
            "jne 5f;"
            "cmpb $'r', 0x4(%1);"
            "jne 5f;"
            "cmpb $'o', 0x5(%1);"
            "jne 5f;"
            "cmpb $'c', 0x6(%1);"
            "jne 5f;"
            "cmpb $'A', 0x7(%1);"
            "jne 5f;"
            "cmpb $'d', 0x8(%1);"
            "jne 5f;"
            "cmpb $'d', 0x9(%1);"
            "jne 5f;"
            "cmpb $'r', 0xa(%1);"
            "je 6f;"
            "5:"
            "movl $0, %0;"
            "jmp 7f;"
            "6:"
            "movl $2, %0;"
            "7:"
            :"=r"(cmp_result2)
            :"S"(pFunctionName)
	);
        if (cmp_result1 == 1)
        {
            pLoadLibrary = (MyLoadLibrary)(pEntry->DllBase + pFunctions[pOrdinals[i]]);
            break;
        }else if(cmp_result2 == 2)
		{
        	pGetProcAddress = (MyGetProcAddress)(pEntry->DllBase + pFunctions[pOrdinals[i]]);
		}
    }
    HMODULE hModule;//LoadLibrary("kernel32.dll)
    __asm__(
    		"push $0;"
            "push $0x6c6c642e;"
            "push $0x32336c65;"
            "push $0x6e72656b;"
            "push %%esp;"
            "call %1;"
            "mov %%eax,%0;"
        	"addl $0x10,%%esp;"
        : "=r" (hModule)
        : "S"(pLoadLibrary)
            );
    VirtualProtectPtr pVirtualProtect;//pGetProcAddress(hModule,"VirtualProtect")
            __asm__(
            "push $0x00007463;"
            "push $0x65746f72;"
            "push $0x506c6175;"
            "push $0x74726956;"
            "push %%esp;"
            "push %2;"
            "call %1;"
        	"mov %%eax,%0;"
        	"addl $0x10,%%esp;"
        : "=r" (pVirtualProtect)
        : "r"(pGetProcAddress),"r"(hModule)
        : "%eax"
            );
    pGetModuleHandleA_ptr pGetModuleHandleA;//pGetProcAddress(hModule,"GetModuleHandleA")
            __asm__(
                "push $0;"
                "push $0x41656c64;"
                "push $0x6e614865;"
                "push $0x6c75646f;"
                "push $0x4d746547;"
                "push %%esp;"
                "push %2;"
                "call %1;"
                "mov %%eax,%0;"
                "addl $0x14,%%esp;"
            : "=r" (pGetModuleHandleA)
            : "r"(pGetProcAddress),"r"(hModule)
            : "%eax"
                );
    hModule;//LoadLibrary("msvcrt.dll")
    __asm__(
    		"push $0x00006c6c;"
            "push $0x642e7472;"
            "push $0x6376736d;"
            "push %%esp;"
            "call %1;"
            "mov %%eax,%0;"
        	"addl $0xc,%%esp;"
        : "=r" (hModule)
        : "S"(pLoadLibrary)
            );
    memset_ptr pmemset;//pGetProcAddress(hModule,"memset")
    __asm__(
            "push $0x00007465;"
            "push $0x736d656d;"
            "push %%esp;"
            "push %2;"
            "call %1;"
        	"mov %%eax,%0;"
        	"addl $0x8,%%esp;"
        : "=r" (pmemset)
        : "r"(pGetProcAddress),"r"(hModule)
        : "%eax"
            );
    memcpy_ptr pmemcpy;//pGetProcAddress(hModule,"memcpy")
            __asm__(
            "push $0x00007970;"
            "push $0x636d656d;"
            "push %%esp;"
            "push %2;"
            "call %1;"
        	"mov %%eax,%0;"
        	"addl $0x8,%%esp;"
        : "=r" (pmemcpy)
        : "r"(pGetProcAddress),"r"(hModule)
        : "%eax"
            );
    malloc_ptr pmalloc;//pGetProcAddress(hModule,"malloc")
        __asm__(
                "push $0x0000636f;"
                "push $0x6c6c616d;"
                "push %%esp;"
                "push %2;"
                "call %1;"
                "mov %%eax,%0;"
                "addl $0x8,%%esp;"
            : "=r" (pmalloc)
            : "r"(pGetProcAddress),"r"(hModule)
            : "%eax"
                );
    FreeFunc pfree;//pGetProcAddress(hModule,"free")
        __asm__(
                "push $0;"
                "push $0x65657266;"
                "push %%esp;"
                "push %2;"
                "call %1;"
                "mov %%eax,%0;"
                "addl $0x8,%%esp;"
            : "=r" (pfree)
            : "r"(pGetProcAddress),"r"(hModule)
            : "%eax"
                );
    //解密部分
    unsigned char* p = (unsigned char*)pack1start+ImageBase;
    DWORD old = 0;
    unsigned char* p_start = p;
    pVirtualProtect(p_start, EncryptSize, PAGE_READWRITE, &old);
    //解密节表
    for(int i=0; i<section_count*0x28; i++)
    {
        *p^=KEY;
        p+=1;
    }
    DWORD old1;
    pVirtualProtect(section_point, section_count*0x28, PAGE_READWRITE, &old1);
    pmemset(section_point,0,2*0x28);
    pmemcpy(section_point,p_start,section_count*0x28);  //复原节区
    void* Chunk = pmalloc(section_count * sizeof(void*));
    void** SectionChunk = (void**)Chunk;
    //解密节
    for(int i=0; i<section_count; i++)
    {
        old1;
        int size_of_section = section_point[i].Misc.VirtualSize;
        unsigned char* secton_start=p;
        for(int i=0; i<size_of_section; i++)
        {
            *(p+i)^=KEY;
        }
        SectionChunk[i] = pmalloc(size_of_section);
        pmemcpy(SectionChunk[i],secton_start,size_of_section);
        p+=size_of_section;
    }
    //数据目录恢复tls，iat
    unsigned char* tls = p;
    for(int i=0; i<TlsSize; i++)
    {
        *p^=KEY;
        p+=1;
    }
    void* tls_tmp = pmalloc(TlsSize);
    pmemcpy(tls_tmp,tls,TlsSize);
    unsigned char* iat = p;
    for(int i=0; i<IatSize; i++)
    {
        *p^=KEY;
        p+=1;
    }
    void* iat_tmp = pmalloc(IatSize);
    pmemcpy(iat_tmp,iat,IatSize);

    for(int i=0;i<section_count;i++){
        int size_of_section = section_point[i].Misc.VirtualSize;
        pVirtualProtect((void*)section_point[i].VirtualAddress+ImageBase, size_of_section, PAGE_READWRITE, &old1);
        if(i<section_count-1){
        pmemset((void*)section_point[i].VirtualAddress+ImageBase,0,section_point[i+1].VirtualAddress-section_point[i].VirtualAddress);
        }else{
        pmemset((void*)section_point[i].VirtualAddress+ImageBase,0,(section_point[i].Misc.VirtualSize+0x1000-1)/0x1000*0x1000);
        }
        pmemcpy((void*)section_point[i].VirtualAddress+ImageBase,SectionChunk[i],size_of_section);
        pfree(SectionChunk[i]);
        DWORD flNewProtect = section_point[i].Characteristics;
        pVirtualProtect((void*)(section_point[i].VirtualAddress+ImageBase), size_of_section, flNewProtect, &old);
    }
    pmemcpy((void*)IatTable+ImageBase,iat_tmp,IatSize);
    pfree(iat_tmp);
    pmemcpy((void*)TlsTable+ImageBase,tls_tmp,TlsSize);
    pfree(tls_tmp);
    pVirtualProtect(section_end, OSectionSize, old, &old);
    //IAT修复
    IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)(ImageBase + (unsigned char*)IatTable);
    while (pImportDesc->Name)
    {
        // 获取导入表的名称
        const char* szName = (char*)(ImageBase + pImportDesc->Name);
        pLoadLibrary(szName);
        // 获取导入表的函数地址
        IMAGE_THUNK_DATA* pThunk = (IMAGE_THUNK_DATA*)(ImageBase + pImportDesc->FirstThunk);
        while (pThunk->u1.Function)
        {
        	if(pThunk->u1.Function>>30 == 1){
        	__asm__(".intel_syntax noprefix\n"
        "nop\n"
        ".att_syntax prefix\n");
			}else{
            // 获取导入表的函数名称
            IMAGE_IMPORT_BY_NAME* pImport = (IMAGE_IMPORT_BY_NAME*)(ImageBase + pThunk->u1.AddressOfData);
			char* szFuncName = (char*)pImport->Name;
            HMODULE hm = pGetModuleHandleA(szName);
            // 修复导入表的函数地址
            DWORD dwFuncAddr = (DWORD)pGetProcAddress(hm, szFuncName);
            pThunk->u1.Function = dwFuncAddr;
            // 继续遍历下一个函数
        }
            pThunk++;
        }
        // 继续遍历下一个导入表
        pImportDesc++;
    }
    //tls初始化
}

//类方法声明
void File_Control::init(const char* Name)
{
    strcpy(FileName,Name);
    read_file();

    //PE头变量赋值
    dos_header=(IMAGE_DOS_HEADER*)StrBuffer;
    nt_headers=(IMAGE_NT_HEADERS*)((BYTE*)StrBuffer + dos_header->e_lfanew);
    optional_headers=&nt_headers->OptionalHeader;
    section_headers=IMAGE_FIRST_SECTION(nt_headers);

    section_count = nt_headers->FileHeader.NumberOfSections;
    SizeOfHeaders = optional_headers->SizeOfHeaders;
    SizeOfImage = optional_headers->SizeOfImage;
    ImageBase = optional_headers->ImageBase;
    OEP = optional_headers->AddressOfEntryPoint;

    //导入表
    IatTable = (_IMAGE_IMPORT_DESCRIPTOR*)(optional_headers->DataDirectory[1].VirtualAddress);
    IatSize = optional_headers->DataDirectory[1].Size;
    //tls目录
    if(optional_headers->DataDirectory[9].VirtualAddress != NULL)
    {
        TlsTable = (_IMAGE_TLS_DIRECTORY32*)(optional_headers->DataDirectory[9].VirtualAddress);
        TlsSize = optional_headers->DataDirectory[9].Size;
    }

    // 判断文件是否是PE文件
    if(dos_header->e_magic != PE_SIGNA)
    {
        output_error(TEXT("文件不是一个可执行文件！"));
    }
    if(nt_headers->Signature != MZ_SIGNA)
    {
        output_error(TEXT("缺少PE头！"));
    }
    if(nt_headers->FileHeader.Machine != MACHINE)
    {
        output_error(TEXT("文件不是一个32位程序！"));
    }
    if(nt_headers->OptionalHeader.Magic != MAGIC)
    {
        output_error(TEXT("文件不是一个32位程序！"));
    }
}
void File_Control::relocat()
{
}
void File_Control::read_file()
{
    FILE* fp;				  // 文件指针
    if ((fp = fopen(FileName, "rb")) == NULL)
    {
        MessageBox(0, TEXT("文件打开失败！"), 0, 0);
        exit(1);
    }
    // 获取文件大小
    fseek(fp, 0, 2);
    FileSize = ftell(fp); // 获取文件指针当前位置相对于文件首的偏移字节数
    fseek(fp, 0, 0);
    StrBuffer=(int *)(malloc(FileSize));
    if (fread(StrBuffer, FileSize, 1, fp) != 1)
    {
        MessageBox(0, TEXT("文件读取失败！"), 0, 0);
        fclose(fp);
        exit(1);
    }
    fclose(fp);
}
void File_Control::create_file(void *Encrypt,int Size)
{
    int UnPackCodeSize =(int)(intptr_t)(void *)&init - (int)(intptr_t)(void *)&unpackcode+sizeof(callunpack);
    //为文件流初始化分配空间
    //壳PE头赋值
    section_point = (IMAGE_SECTION_HEADER*)(NewDosHeader.e_lfanew+NewFileHeader.SizeOfOptionalHeader+0x18+ImageBase);
    section_end = (void*)(section_headers[section_count-1].VirtualAddress + MemoryAlignment(section_headers[section_count-1].Misc.VirtualSize));
    NewOptionHeader.BaseOfCode = section_headers[0].VirtualAddress;
    NewOptionHeader.ImageBase = ImageBase;
    NewOptionHeader.SizeOfHeaders = MemoryAlignment(NewDosHeader.e_lfanew+NewFileHeader.SizeOfOptionalHeader+0x18+section_count*0x28);//原程序节结尾,存放unpackcode的位置
    //pack2 virutaladdress
    int pack2start = NewOptionHeader.BaseOfCode+FileAlignment(Size);
    OSectionSize = section_headers[section_count-1].VirtualAddress + MemoryAlignment(section_headers[section_count-1].Misc.VirtualSize) - MemoryAlignment(pack2start);  //原程序节结尾到pack1结尾的大小
    if(OSectionSize<0)
    {
        OSectionSize=0;
        NewOptionHeader.AddressOfEntryPoint = pack2start;
    }
    else
    {
        NewOptionHeader.AddressOfEntryPoint = MemoryAlignment(NewOptionHeader.BaseOfCode) + MemoryAlignment(Size) + OSectionSize;
    }
    int file_size;
    file_size=NewOptionHeader.SizeOfHeaders+MemoryAlignment(UnPackCodeSize)+OSectionSize+MemoryAlignment(Size)+0x10;
    char* filebuffer = (char*)malloc(file_size);
    memset(filebuffer,0,file_size);
    if(filebuffer == NULL)
    {
        printf("动态申请filebuffer失败!!!!\n");
        exit(0);
    }


    //PE头声明
    IMAGE_DOS_HEADER* pDosHeader = NULL;
    IMAGE_NT_HEADERS* pNTHeader = NULL;
    IMAGE_FILE_HEADER* pPEHeader = NULL;
    IMAGE_OPTIONAL_HEADER32* pOptionHeader = NULL;
    IMAGE_SECTION_HEADER* pSectionHeader = NULL;
    IMAGE_SECTION_HEADER* pSectionHeader2 = NULL;
    pDosHeader = (IMAGE_DOS_HEADER*)(char*)filebuffer;
    pNTHeader = (IMAGE_NT_HEADERS*)((char*)filebuffer+NewDosHeader.e_lfanew);
    pPEHeader = &pNTHeader->FileHeader;
    pOptionHeader = &pNTHeader->OptionalHeader;
    //DosHeader
    pDosHeader->e_magic=NewDosHeader.e_magic;
    pDosHeader->e_cblp=NewDosHeader.e_cblp;
    pDosHeader->e_cp=NewDosHeader.e_cp;
    pDosHeader->e_cparhdr=NewDosHeader.e_cparhdr;
    pDosHeader->e_minalloc=NewDosHeader.e_minalloc;
    pDosHeader->e_maxalloc=NewDosHeader.e_maxalloc;
    pDosHeader->e_ss=NewDosHeader.e_ss;
    pDosHeader->e_sp=NewDosHeader.e_sp;
    pDosHeader->e_csum=NewDosHeader.e_csum;
    pDosHeader->e_ip=NewDosHeader.e_ip;
    pDosHeader->e_cs=NewDosHeader.e_cs;
    pDosHeader->e_lfarlc=NewDosHeader.e_lfarlc;
    pDosHeader->e_ovno=NewDosHeader.e_ovno;
    pDosHeader->e_res[0]=NewDosHeader.e_res[0];
    pDosHeader->e_res[1]=NewDosHeader.e_res[1];
    pDosHeader->e_res[2]=NewDosHeader.e_res[2];
    pDosHeader->e_res[3]=NewDosHeader.e_res[3];
    pDosHeader->e_oemid=NewDosHeader.e_oemid;
    pDosHeader->e_oeminfo=NewDosHeader.e_oeminfo;
    pDosHeader->e_res2[0]=NewDosHeader.e_res2[0];
    pDosHeader->e_res2[1]=NewDosHeader.e_res2[1];
    pDosHeader->e_res2[2]=NewDosHeader.e_res2[2];
    pDosHeader->e_res2[3]=NewDosHeader.e_res2[3];
    pDosHeader->e_res2[4]=NewDosHeader.e_res2[4];
    pDosHeader->e_res2[5]=NewDosHeader.e_res2[5];
    pDosHeader->e_res2[6]=NewDosHeader.e_res2[6];
    pDosHeader->e_res2[7]=NewDosHeader.e_res2[7];
    pDosHeader->e_res2[8]=NewDosHeader.e_res2[8];
    pDosHeader->e_res2[9]=NewDosHeader.e_res2[9];
    pDosHeader->e_lfanew=NewDosHeader.e_lfanew;
    //NTHeader
    pNTHeader->Signature = NewNTHeader.Signature;
    //FileHeader
    pPEHeader->Machine = NewFileHeader.Machine;
    pPEHeader->NumberOfSections = NewFileHeader.NumberOfSection;
    pPEHeader->TimeDateStamp = NewFileHeader.TimeDateStamp;
    pPEHeader->PointerToSymbolTable = NewFileHeader.PointerToSymbolTable;
    pPEHeader->NumberOfSymbols = NewFileHeader.NumberOfSection;
    pPEHeader->SizeOfOptionalHeader = NewFileHeader.SizeOfOptionalHeader;
    pPEHeader->Characteristics = NewFileHeader.Characteristics;
    //OptionHeader
    pOptionHeader->Magic = NewOptionHeader.Magic;
    pOptionHeader->MajorLinkerVersion = 0x2;
    pOptionHeader->MinorLinkerVersion = 0x18;
    pOptionHeader->SizeOfCode = NewOptionHeader.SizeOfCode;
    pOptionHeader->SizeOfInitializedData = NewOptionHeader.SizeOfInitializedData;
    pOptionHeader->SizeOfUninitializedData = NewOptionHeader.SizeOfUninitializedData;
    pOptionHeader->AddressOfEntryPoint = NewOptionHeader.AddressOfEntryPoint;
    pOptionHeader->BaseOfCode = NewOptionHeader.BaseOfCode;
    pOptionHeader->BaseOfData = NewOptionHeader.BaseOfData;
    pOptionHeader->ImageBase = NewOptionHeader.ImageBase;
    pOptionHeader->SectionAlignment = NewOptionHeader.SectionAlignment;
    pOptionHeader->FileAlignment = NewOptionHeader.FileAlignment;
    pOptionHeader->MajorOperatingSystemVersion = NewOptionHeader.MajorOperatingSystemVersion;
    pOptionHeader->MinorOperatingSystemVersion = NewOptionHeader.MinorOperatingSystemVersion;
    pOptionHeader->MajorImageVersion = NewOptionHeader.MajorImageVersion;
    pOptionHeader->MinorImageVersion = NewOptionHeader.MinorImageVersion;
    pOptionHeader->MajorSubsystemVersion = NewOptionHeader.MajorSubsystemVersion;
    pOptionHeader->MinorSubsystemVersion = NewOptionHeader.MinorSubsystemVersion;
    pOptionHeader->Win32VersionValue = NewOptionHeader.Win32VersionValue;
    pOptionHeader->SizeOfHeaders = NewOptionHeader.SizeOfHeaders;
    pOptionHeader->CheckSum = NewOptionHeader.CheckSum;
    pOptionHeader->Subsystem = optional_headers->Subsystem;
    pOptionHeader->DllCharacteristics = NewOptionHeader.DllCharacteristics;
    pOptionHeader->SizeOfStackReserve = NewOptionHeader.SizeOfStackReserve;
    pOptionHeader->SizeOfStackCommit = NewOptionHeader.SizeOfStackCommit;
    pOptionHeader->SizeOfHeapReserve = NewOptionHeader.SizeOfHeapReserve;
    pOptionHeader->SizeOfHeapCommit = NewOptionHeader.SizeOfHeapCommit;
    pOptionHeader->LoaderFlags = NewOptionHeader.LoaderFlags;
    pOptionHeader->NumberOfRvaAndSizes = NewOptionHeader.NumberOfRvaAndSizes;


    //
    int SizeOfRawData = RvaToFoa(section_headers[section_count-1].VirtualAddress);
    //SectionHeader pack1
    pSectionHeader = (IMAGE_SECTION_HEADER*)((char*)pOptionHeader+sizeof(IMAGE_OPTIONAL_HEADER32));
    strcpy((char*)pSectionHeader->Name,".pack1");
    pSectionHeader->Misc.VirtualSize = Size;
    pSectionHeader->VirtualAddress = section_headers[0].VirtualAddress;
    pSectionHeader->SizeOfRawData = FileAlignment(Size);
    pSectionHeader->PointerToRawData = pOptionHeader->SizeOfHeaders;
    pSectionHeader->PointerToRelocations = 0;
    pSectionHeader->PointerToLinenumbers = 0;
    pSectionHeader->NumberOfRelocations = 0;
    pSectionHeader->NumberOfLinenumbers = 0;
    pSectionHeader->Characteristics = 0xC0000040;
    //SectionHeader2 pack2
    pSectionHeader2 = (IMAGE_SECTION_HEADER*)((char*)pSectionHeader+sizeof(IMAGE_SECTION_HEADER));
    strcpy((char*)pSectionHeader2->Name,".pack2");
    pSectionHeader2->VirtualAddress = MemoryAlignment(pSectionHeader->Misc.VirtualSize) + pSectionHeader->VirtualAddress;
    pSectionHeader2->Misc.VirtualSize = UnPackCodeSize+OSectionSize;//节2大小=解密壳大小+原程序结尾到pack1结尾大小
    int UPCS = FileAlignment(UnPackCodeSize);//解密壳大小内存对齐后的大小
    pSectionHeader2->SizeOfRawData =  OSectionSize + UPCS;
    pSectionHeader2->PointerToRawData = pSectionHeader->SizeOfRawData+pSectionHeader->PointerToRawData;
    pSectionHeader2->PointerToRelocations = 0;
    pSectionHeader2->PointerToLinenumbers = 0;


    pSectionHeader2->NumberOfRelocations = 0;
    pSectionHeader2->NumberOfLinenumbers = 0;
    pSectionHeader2->Characteristics = 0x60000020;


    //SizeOfImage计算
    pOptionHeader->SizeOfImage = pSectionHeader2->VirtualAddress+pSectionHeader2->SizeOfRawData;
    //pack节赋值
    char* pData = (char*)((char*)filebuffer+pSectionHeader->PointerToRawData);
    memset(pData,0,sizeof(pData));
    memcpy(pData,Encrypt,Size);

    //unpackcode变量初始化
    memcpy(&callunpack[2],&OEP,sizeof(int));    //file OEP
    memcpy(&callunpack[7], &IatSize, sizeof(int)); //fill IatSize
    memcpy(&callunpack[12], &TlsSize, sizeof(int)); //fill TlsSize
    memcpy(&callunpack[17], &IatTable, sizeof(_IMAGE_IMPORT_DESCRIPTOR*)); //fill IatTable
    memcpy(&callunpack[22], &TlsTable, sizeof(_IMAGE_TLS_DIRECTORY32*)); //fill TlsTable
    memcpy(&callunpack[27], &OSectionSize, sizeof(int)); //fill OSectionSize
    memcpy(&callunpack[32], &section_end, sizeof(int)); //fill section_end
    memcpy(&callunpack[37], &section_point, sizeof(int)); //fill section_point
    memcpy(&callunpack[42], &section_count, sizeof(void*)); //fill section_count
    memcpy(&callunpack[47], &EncryptSize, sizeof(int)); //fill EncryptSize
    memcpy(&callunpack[52], &(pSectionHeader->VirtualAddress), sizeof(int)); //fill SizeOfHeaders
    memcpy(&callunpack[57], &ImageBase, sizeof(int)); //fill ImageBase
    int offset = (int)(OEP-(NewOptionHeader.AddressOfEntryPoint+sizeof(callunpack)));
    memcpy(&callunpack[68], &offset, sizeof(int));

    char* pCode = (char*)((char*)filebuffer + pSectionHeader2->PointerToRawData + OSectionSize);
//    relocat();
    memcpy(pCode,(void*)&callunpack,sizeof(callunpack));
    memcpy(pCode+sizeof(callunpack),(void*)&unpackcode,UnPackCodeSize);

    //生成完毕
    printf("加壳文件生成成功!\n");
//    unpackcode(ImageBase,SizeOfHeaders,EncryptSize,section_count,section_point,section_end,OSectionSize,TlsTable,IatTable,TlsSize,IatSize,OEP);
    char unpackfilename[strlen(FileName)+6]="";
    memset(unpackfilename,0,strlen(FileName)+6);
    memcpy(unpackfilename,FileName,strlen(FileName)-4);
    strcat(unpackfilename,"_pack.exe");
    FILE* file=fopen(unpackfilename,"wb+");
    fwrite(filebuffer,file_size,1,file);
    fclose(file);
}
void File_Control::output_error(const TCHAR* error_message)
{
    MessageBox(0, error_message, 0, 0);
    exit(1);
}
void* File_Control::encrypt(unsigned char* text,int size)
{
    unsigned char *Etext=(unsigned char *)malloc(size);
    for(int i=0; i<size; i++)
    {
        *(Etext+i)= *(text+i)^KEY;
    }
    return Etext;
}
void File_Control::pack()
{
    //Encrypt声明
    EncryptSize =(section_count*0x28);
    for(int i=0; i<section_count; i++)        //遍历所有节表获取节大小
    {
        EncryptSize+=section_headers[i].Misc.VirtualSize;
    }
    if(TlsTable != NULL)
        EncryptSize+=TlsSize;
    EncryptSize+=IatSize;
    void* Encrypt = malloc(EncryptSize);
    void* tmp=Encrypt;
    void* t=tmp;
    //加密所有节以及所有节表，存储到Encrypt
    void *Etext=encrypt((unsigned char*)section_headers,0x28*section_count);
    memcpy(tmp,Etext,0x28*section_count);
    tmp+=0x28*section_count;
    for(int i=0; i<section_count; i++)
    {
        int SectionAddress = section_headers[i].PointerToRawData;
        int SectionSize = section_headers[i].Misc.VirtualSize;
        if(section_headers[i].SizeOfRawData!=0){
        void *Etext=encrypt(((unsigned char*)StrBuffer+SectionAddress),SectionSize);
        memcpy(tmp,Etext,SectionSize);
        tmp+=SectionSize;
        }else{
        void* uninitsection = malloc(SectionSize);
        memset(uninitsection,0,SectionSize);
        void *Etext=encrypt((unsigned char*)uninitsection,SectionSize);
        memcpy(tmp,Etext,SectionSize);
        tmp+=SectionSize;
        }
    }
    //保存tls目录
    if(TlsTable != NULL){
        void *Etext = encrypt((unsigned char*)StrBuffer+RvaToFoa((DWORD)TlsTable),TlsSize);
        memcpy(tmp,(void*)Etext,TlsSize);
    }
    tmp+=TlsSize;
    //保存导入表
    Etext = encrypt((unsigned char*)StrBuffer+RvaToFoa((DWORD)IatTable),IatSize);
    memcpy(tmp,Etext,IatSize);
    //输出加壳后文件
    create_file(Encrypt,EncryptSize);
}
DWORD File_Control::RvaToFoa(DWORD dwRva)
{
    DWORD dwFoa = 0;
    for (WORD i = 0; i < section_count; i++)
    {
        if (dwRva >= section_headers[i].VirtualAddress && dwRva < section_headers[i].VirtualAddress + section_headers[i].Misc.VirtualSize)
        {
            dwFoa = dwRva - section_headers[i].VirtualAddress + section_headers[i].PointerToRawData;
            break;
        }
    }
    return dwFoa;
}
//主函数
int main(int argc, char* argv[])
{
    File_Control file;		//文件操作对象
    if (debug)
    {
        file.init("base.exe");
    }
    else
    {
        if (argc <2)
        {
            printf("用法: %s <path_of_injected_file>\n","injection.exe");
        }
        if(sizeof(argv[1])>=100)
            file.output_error("文件路径过长！");
        file.init(argv[1]);
    }
    if (debug)
        printf("打开文件成功!\n");

    file.pack();
}
