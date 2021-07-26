#include "util.h"

/*
Name: util.c
Desc: util func
*/
__forceinline wchar_t locase_w(wchar_t c)
{
	if ((c >= 'A') && (c <= 'Z'))
		return c + 0x20;
	else
		return c;
}

int _strcmpi_w(const wchar_t* s1, const wchar_t* s2)
{
	wchar_t c1, c2;

	if (s1 == s2)
		return 0;

	if (s1 == 0)
		return -1;

	if (s2 == 0)
		return 1;

	do {
		c1 = locase_w(*s1);
		c2 = locase_w(*s2);
		s1++;
		s2++;
	} while ((c1 != 0) && (c1 == c2));

	return (int)(c1 - c2);
}

char locase(char s1)
{
	if ((s1 >= 'A') && ((s1) <= 'Z'))
		return s1 + 0x20;
	else
		return s1;
}

int _strcmpni_(char* s1, char* s2)
{
	char c1,c2;

	if (s1 == s2)
		return 0;

	do {
		c1 = locase(*s1);
		c2 = locase(*s2);
		s1++;
		s2++;
	} while ((c1 != 0) && (c1 == c2));

	return (int)(c1 - c2);
}

PVOID FindAddressinKernel(PDRIVER_OBJECT pDriver)
{
	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	PLDR_DATA_TABLE_ENTRY first = entry;
	while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
	{
		if (!_strcmpi_w(entry->BaseDllName.Buffer, L"ntoskrnl.exe"))
		{
			return entry->DllBase;
		}
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
	return 0;
}

PVOID FindPattern(PVOID pvAddress, UINT64 qwLen, char* bMask, const char* szMask)
{
	
	char* FindData;
	if (!pvAddress)
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] No Module Address\n");
	if(!qwLen)
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] No Module SizeOfImage\n");
	//DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] qwNtSizeofImaged %x \n",qwLen);
	FindData = ExAllocatePoolWithTag(PagedPool, sizeof(char) * qwLen, 51);
	memmove(FindData, pvAddress, sizeof(char)*qwLen);
	UINT64 qwMaxLen = qwLen - strlen(szMask);
	for (UINT64 i = 0; i < qwMaxLen; i++)
		if (bDataCompare((char*)(FindData+i), bMask, szMask))
			return (PVOID)((UINT64)pvAddress + i) ;
	return 0;
}

PVOID FindPatternInSection(PVOID pvAddress,char* SectionName,char* bMask, const char* szMask)
{
	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS64 NTHeader;
	IMAGE_SECTION_HEADER SectionHeader;
	UINT64 qwSectionSize = 0;
	UINT64 qwSectionAddress = 0;
	

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] qwNtAddress: %p \n", pvAddress);
	memmove(&DosHeader, pvAddress, sizeof(IMAGE_DOS_HEADER));
	if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Can't Copy DosHeader \n");

	memmove(&NTHeader, (PVOID)((UINT64)pvAddress+ DosHeader.e_lfanew), sizeof(IMAGE_NT_HEADERS64));
	if (NTHeader.Signature != IMAGE_NT_SIGNATURE)
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Can't Copy NTHeader \n");	

	for (UINT64 i = 0; i < NTHeader.FileHeader.NumberOfSections; i++)
	{
		memmove(&SectionHeader, (PVOID)((UINT64)pvAddress + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64)+sizeof(IMAGE_SECTION_HEADER)*i), sizeof(IMAGE_SECTION_HEADER));
		if (!_strcmpni_(SectionHeader.Name,SectionName)) 
		{
			qwSectionSize = SectionHeader.SizeOfRawData;
			qwSectionAddress = SectionHeader.VirtualAddress;
			break;
		}
	}

	if (qwSectionSize == 0 && qwSectionAddress == 0)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Can't Find Section \n");
		return 0;
	}
	
	return FindPattern((PVOID)((UINT64)pvAddress + qwSectionAddress), qwSectionSize, bMask, szMask);
}

PVOID ResolveRelativeAddress(PVOID pvAddress,UINT64 qwOffset,UINT64 qwRelative)
{
	ULONG ulRelativeAddress;
	memmove(&ulRelativeAddress, (PVOID)((UINT64)pvAddress + qwOffset), sizeof(ULONG));
	return (PVOID)(ulRelativeAddress + (UINT64)pvAddress + qwRelative);
}

BOOLEAN FreeObjectType(PDRIVER_OBJECT pDriver, POBJECT_TYPE pObjectType,POBJECT_TYPE pDbgObjType ,UINT64 qwAddress)
{
	PVOID pvNtAddress, pvTypeIndexTable, pvAddress;
	pvAddress = FindAddressinKernel(pDriver);

	pvNtAddress = FindPatternInSection(pvAddress,(char*)".text", (char*)"\x48\x8b\xc1\x4c\x8d\x0d\x00\x00\x00\x00\x48\xc1\xe8\x08",(char*)"xxxxxx????xxxx");
	if (pvNtAddress == NULL)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Can't find a pattern in section\n");
		return FALSE;
	}

	pvTypeIndexTable = ResolveRelativeAddress(pvNtAddress, 6, 10);

	//thx for shh0ya
	RtlZeroMemory((PVOID)((UINT64)pvTypeIndexTable+(0x08*pObjectType->Index)), 8); // Delete 
	memmove((PVOID)qwAddress, &pDbgObjType, 8);
	return TRUE;
}

BOOLEAN bDataCompare(const char* pData, const char* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;
	return (*szMask) == 0;
} 