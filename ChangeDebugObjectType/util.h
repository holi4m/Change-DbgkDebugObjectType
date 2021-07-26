/*
Name: util.h
Desc: Define function and value use in util.c
*/
#include "struct.h"

// define User Function
void* FindAddressinKernel(PDRIVER_OBJECT pDriver);
PVOID FindPattern(PVOID pvAddress, UINT64 qwLen, char* bMask, const char* szMask);
BOOLEAN bDataCompare(const char* pData, const char* bMask, const char* szMask);
PVOID FindPatternInSection(PVOID pvAddress, char* SectionName, char* bMask, const char* szMask);
PVOID ResolveRelativeAddress(PVOID pvAddress, UINT64 qwOffset, UINT64 qwRelative);
BOOLEAN FreeObjectType(PDRIVER_OBJECT pDriver, POBJECT_TYPE pObjectType, POBJECT_TYPE pDbgObjType, UINT64 qwAddress);