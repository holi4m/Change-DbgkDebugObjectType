#include "driver.h"


NTSTATUS CreateObjectType()
{
	OBJECT_TYPE_INITIALIZER ObjectTypeInitializer;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING Name;

	RtlZeroMemory(&ObjectTypeInitializer, sizeof(OBJECT_TYPE_INITIALIZER)); // Initalize ObjectTypeInitializer 
	ObjectTypeInitializer.Length = sizeof(OBJECT_TYPE_INITIALIZER); // Set ObjectTypeInitalizer Length
	ObjectTypeInitializer.ValidAccessMask = DEBUG_ALL_ACCESS;
	ObjectTypeInitializer.CloseProcedure = pDbgObjType->TypeInfo.CloseProcedure;
	ObjectTypeInitializer.DeleteProcedure = pDbgObjType->TypeInfo.DeleteProcedure;
	
	RtlInitUnicodeString(&Name, L"Holiam"); // Set Name
	ntStatus = ObCreateObjectType(&Name, &ObjectTypeInitializer, 0, &pObjectType);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Object Address: %p\n", &pObjectType);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] ObCreateObjectType Error\n");
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Error NTSTATUS : %x \n", ntStatus);
	}

	return ntStatus;
}


VOID UnloadDriver(IN PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);
	//FreeObjectType(pDriver, pObjectType,pDbgObjType,qwDbgObjectTypeAddress); // Developing
	
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Unload Driver\n");
}


NTSTATUS DriverEntry(
	IN PDRIVER_OBJECT pDriver,
	IN PUNICODE_STRING pRegPath
)
{
	UNREFERENCED_PARAMETER(pDriver);
	UNREFERENCED_PARAMETER(pRegPath);

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Load Driver\n");
	pDriver->DriverUnload = UnloadDriver;

	NTSTATUS ret = STATUS_SUCCESS;
	UINT64 qwDbgObjectPatternAddress;
	
	//find ntoskrnl.exe addr
	pvNtAddress = FindAddressinKernel(pDriver);

	//find the DbgkDebugObjectType pattern
	qwDbgObjectPatternAddress = (UINT64)FindPatternInSection(pvNtAddress, (char*)"PAGE", (char*)"\x48\x8b\x05\x00\x00\x00\x00\x41\xb9\x00\x00\x00\x02", (char*)"xxx????xxxxxx");
	if (qwDbgObjectPatternAddress == 0)
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Can't find KernelAddress \n");

	qwDbgObjectTypeAddress = (UINT64)ResolveRelativeAddress((PVOID)qwDbgObjectPatternAddress, 3, 7);

	//backup Original "DebugObject"
	memmove(&pDbgObjType, (PVOID)qwDbgObjectTypeAddress, 8);
	if(&pDbgObjType == NULL)
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Can't Copy DbgkDebugObjectType \n");
	//create object type
	ret = CreateObjectType();

	if (ret != STATUS_SUCCESS)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Failed a Registration\n");
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Error NTSTATUS : %x \n", ret);
	}

	//Change DbgkDebugObjectType
	memmove((PVOID)qwDbgObjectTypeAddress, pObjectType, 8);

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Changed done \n");
	return STATUS_SUCCESS;
}