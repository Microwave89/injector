Enter file contents here#include "global.h"

#define MIN_VM_ACCESS_MASK ( PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)

UCHAR sg_pFullImageHdr[PAGE_SIZE];

NTSTATUS openProcByName(PHANDLE pProcess, PUNICODE_STRING pProcName, BOOLEAN useDebugPrivilege){
	SYSTEM_PROCESS_INFORMATION procInfo;
	OBJECT_ATTRIBUTES procAttr;
	OBJECT_BASIC_INFORMATION processHandleInfo;
	CLIENT_ID cid;
	BOOLEAN oldValue;
	HANDLE pid;

	NTSTATUS status = STATUS_CACHE_PAGE_LOCKED;
	ULONG procListSize = 0;
	ULONGLONG memSize = 0;
	ULONG obQueryLen = 0;
	PVOID pProcListHead = NULL;
	PSYSTEM_PROCESS_INFORMATION pProcEntry = NULL;

	if (!pProcName || !pProcess)
		return STATUS_INVALID_PARAMETER;

	*pProcess = NULL;

	///Since we specify a buffer size of 0 the buffer must overflow for sure even if there was running a
	///single process only. If we don't receive the dedicated error, something other has gone wrong
	///and we cannot rely on the return length.
	status = NtQuerySystemInformation(SystemProcessInformation, &procInfo, procListSize, &procListSize);
	if (STATUS_INFO_LENGTH_MISMATCH != status)
		return status;

	memSize = PAGE_ROUND_UP(procListSize) + PAGE_SIZE; ///We better allocate one page extra
	///since between our "test" call and the real call below
	///additional processes might be started. (race condition)
	status = NtAllocateVirtualMemory(INVALID_HANDLE_VALUE, &pProcListHead, 0, &memSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (status)
		return status;

	///By now, we have allocated a buffer large enough for the complete process list,
	///even if some new processes have been started in the mean time.
	///Hence, the next call is entirely expected to succeed.
	procListSize = (ULONG)memSize;
	status = NtQuerySystemInformation(SystemProcessInformation, pProcListHead, procListSize, &procListSize);
	if (status){
		memSize = 0;
		NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pProcListHead, &memSize, MEM_RELEASE);
		return status;
	}

	pid = NULL;
	pProcEntry = pProcListHead;				///The list of all system processes is a so called singly linked list.
	while (pProcEntry->NextEntryOffset){	///If NextEntryOffset member is NULL, we have reached the list end (tail).
		pProcEntry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pProcEntry + pProcEntry->NextEntryOffset);
		//DebugPrint2A("PID: %d, %wZ", pProcEntry->UniqueProcessId, pProcEntry->ImageName);
		if (0 == RtlCompareUnicodeString(pProcName, &pProcEntry->ImageName, TRUE)){
			pid = pProcEntry->UniqueProcessId;
			break;
		}
	}

	memSize = 0;
	NtFreeVirtualMemory(INVALID_HANDLE_VALUE, &pProcListHead, &memSize, MEM_RELEASE); ///We don't need the list anymore.

	if (!pid)
		return STATUS_OBJECT_NAME_NOT_FOUND;

	//DebugPrint2A("%wZ pid = %llu", *pProcName, pid);

	if (useDebugPrivilege){
		status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &oldValue);
		if (status)			///Since we're for some reason supposed to use the SeDebugPrivilege,
			return status;	///we fail deliberately if we can't enable it. 
	}

	InitializeObjectAttributes(&procAttr, NULL, 0, NULL, NULL);
	cid.UniqueThread = (HANDLE)0;
	cid.UniqueProcess = pid;
	///Opening a process for full access might be less suspicious than opening with our real intentions.
	status = NtOpenProcess(pProcess, PROCESS_ALL_ACCESS, &procAttr, &cid);

	if (useDebugPrivilege)
		///We don't have any clue if the privilege already was enabled,
		///so we simply restore the old status. Whether we do this call or not 
		///isn't anyhow related to the result of process opening.
		RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, oldValue, FALSE, &oldValue);

	if (status)
		return status;   ///Most likely STATUS_ACCESS_DENIED if
	///either we didn't specify the useDebugPrivilege flag when opening a cross session process
	///or if we tried to open an elevated process while running non-elevated.

	///In x64 windows, HIPS or AV drivers have the possibility to legally
	///receive a notification if a process is about to open a handle to another process.
	///In those ObCallback routines they cannot completely deny the opening.
	///However, they are able to modify the access masks, so a handle supposed for VM operations still
	///will be lacking the PROCESS_VM_XXX rights, for example. If we therefore query the handle rights
	///we can still return an appropriate error if wasn't granted the rights we want
	///And are not going to fail at first when performing our process operations.
	status = NtQueryObject(*pProcess, ObjectBasicInformation, &processHandleInfo, sizeof(OBJECT_BASIC_INFORMATION), &obQueryLen);
	if (status){	///Not sure if this call ever will fail...
		NtClose(*pProcess);
		*pProcess = NULL;
		return status;
	}

	///Maybe, HIPS just wanted to deny PROCESS_TERMINATE/PROCESS_SUSPEND right?
	///If so, we don't care. We're only interested in VM rights.
	if (MIN_VM_ACCESS_MASK & ~processHandleInfo.GrantedAccess){
		NtClose(*pProcess);
		*pProcess = NULL;
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}



NTSTATUS findCodeCave(HANDLE hProcess, PVOID* pCodeCave, ULONGLONG desiredSize, PULONGLONG pActualSize){
	MEMORY_BASIC_INFORMATION freeMemInfo;
	MEMORY_BASIC_VLM_INFORMATION imageOrMappingInfo;
	IMAGE_SECTION_HEADER currSecHdr;
	ULONG oldProt;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pCurrAddress = NULL;
	PIMAGE_NT_HEADERS64 pPeHdr64 = NULL;
	ULONGLONG resultLen = 0;
	BOOLEAN queryFreeMem = FALSE;
	ULONGLONG fullImageHdrSize = PAGE_SIZE;

	PIMAGE_SECTION_HEADER pFirstSecHdr = NULL;

	if (!pActualSize || !desiredSize || !pActualSize || !pCodeCave)
		return STATUS_INVALID_PARAMETER;
	
	desiredSize = ALIGN_UP(desiredSize, 0x10);
	*pActualSize = 0;
	RtlZeroMemory(&freeMemInfo, sizeof(MEMORY_BASIC_INFORMATION));
	RtlZeroMemory(&imageOrMappingInfo, sizeof(MEMORY_BASIC_VLM_INFORMATION));

	for (;;){
		if (queryFreeMem)
			status = NtQueryVirtualMemory(hProcess, pCurrAddress, MemoryBasicInformation, &freeMemInfo, sizeof(MEMORY_BASIC_INFORMATION), &resultLen);
		else
			status = NtQueryVirtualMemory(hProcess, pCurrAddress, MemoryBasicVlmInformation, &imageOrMappingInfo, sizeof(MEMORY_BASIC_VLM_INFORMATION), &resultLen);
		if (STATUS_INVALID_ADDRESS == status){
			queryFreeMem = TRUE;
			continue;
		}
		if (STATUS_INVALID_PARAMETER == status)
			break;
		if (status)
			return status;
		
		if (queryFreeMem){
			pCurrAddress = (PUCHAR)pCurrAddress + freeMemInfo.RegionSize;
			queryFreeMem = FALSE;
			continue;
		}
		else {
			pCurrAddress = (PUCHAR)pCurrAddress + imageOrMappingInfo.SizeOfImage;
			queryFreeMem = FALSE;
		}		

		if (MEM_IMAGE != imageOrMappingInfo.Type)
			continue;

		OutputDebugStringA("Memory Basic Vlm Info | Found an Image!");
		DebugPrint2A("memVlmInfo.Type: %llX", imageOrMappingInfo.Type);
		DebugPrint2A("memVlmInfo.Protection: %llX", imageOrMappingInfo.Protection);
		DebugPrint2A("memVlmInfo.ImageBase: %p", imageOrMappingInfo.ImageBase);
		DebugPrint2A("memVlmInfo.SizeOfImage: %llX", imageOrMappingInfo.SizeOfImage);
		DebugPrint2A("memVlmInfo.Unknown: %llX", imageOrMappingInfo.Unknown);
		
		status = NtProtectVirtualMemory(hProcess, (PVOID)&imageOrMappingInfo.ImageBase, &fullImageHdrSize, PAGE_READONLY, &oldProt);
		if (status)
			continue;

		DebugPrint2A("memVlmInfo.ImageBase: %p", imageOrMappingInfo.ImageBase);
		status = NtReadVirtualMemory(hProcess, (PVOID)imageOrMappingInfo.ImageBase, sg_pFullImageHdr, sizeof(sg_pFullImageHdr), &fullImageHdrSize);
		if (status)
			continue;

		pPeHdr64 = (PIMAGE_NT_HEADERS64)(sg_pFullImageHdr + ((PIMAGE_DOS_HEADER)sg_pFullImageHdr)->e_lfanew);
		if (IMAGE_NT_SIGNATURE != pPeHdr64->Signature)
			continue;
		
		pFirstSecHdr = IMAGE_FIRST_SECTION(pPeHdr64);
		for (ULONG i = 0; i < pPeHdr64->FileHeader.NumberOfSections; i++){
			currSecHdr = pFirstSecHdr[i];
			DebugPrint2A("%lX", currSecHdr.Characteristics);
			if (currSecHdr.Characteristics & IMAGE_SCN_MEM_EXECUTE){
				DebugPrint2A("Executable section starts @ %p with size %llX", (sg_pFullImageHdr + PAGE_ROUND_UP(currSecHdr.VirtualAddress)), currSecHdr.Misc.VirtualSize);
			}
		}
	}
	return STATUS_SUCCESS;
}


void mymain(void){
	NTSTATUS status = STATUS_GENERIC_NOT_MAPPED;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	UNICODE_STRING uProcName;
	PVOID pCodeCave = NULL;
	ULONGLONG actualSize = 0;
	RtlInitUnicodeString(&uProcName, L"notepad.exe");

	status = openProcByName(&hProcess, &uProcName, FALSE);
	if (status){
		NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
		return;
	}

	//DebugPrint2A("Success! Full or VM access handle: %p", hProcess);
	status = findCodeCave(hProcess, &pCodeCave, 89, &actualSize);
	if (status){
		NtRaiseHardError(status, 0, 0, NULL, 0, (PULONG)&status);
		return;
	}
}
