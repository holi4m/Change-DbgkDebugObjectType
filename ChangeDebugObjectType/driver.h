/*
# Name : define.h
# Desc : defined function and value use in driver.c
*/

#pragma once
#include "util.h"

POBJECT_TYPE pObjectType;
POBJECT_TYPE pDbgObjType;
UINT64 qwDbgObjectTypeAddress;
UINT64 qwDbgObjectTypeIndex;
PVOID pvNtAddress;

// define DrvierEntry, Unload Driver
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath);
VOID UnloadDriver(IN PDRIVER_OBJECT pDriver);
NTSTATUS CreateObjectType();

// define undocument kernel function
NTSTATUS ObCreateObjectType(
	__in PUNICODE_STRING TypeName,
	__in POBJECT_TYPE_INITIALIZER ObjectTypeInitializer,
	__in_opt PSECURITY_DESCRIPTOR SecurityDescriptor,
	__out POBJECT_TYPE* ObjectType
);


