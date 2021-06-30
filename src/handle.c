//https://www.cplusplus.com/forum/windows/95774/

#include <windows.h>
#include <stdio.h>

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS (NTAPI *_NtQuerySystemInformation)(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *_NtDuplicateObject)(
		HANDLE SourceProcessHandle,
		HANDLE SourceHandle,
		HANDLE TargetProcessHandle,
		PHANDLE TargetHandle,
		ACCESS_MASK DesiredAccess,
		ULONG Attributes,
		ULONG Options
);

typedef NTSTATUS (NTAPI *_NtQueryObject)(
		HANDLE ObjectHandle,
		ULONG ObjectInformationClass,
		PVOID ObjectInformation,
		ULONG ObjectInformationLength,
		PULONG ReturnLength
);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName) {
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}


int FindAndCloseWAHandle() {
	_NtQuerySystemInformation NtQuerySystemInformation =
			GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtQueryObject NtQueryObject =
			GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	ULONG pid = GetCurrentProcessId();
	HANDLE processHandle = GetCurrentProcess();
	ULONG i;
	int ret = 0;
	handleInfo = (PSYSTEM_HANDLE_INFORMATION) malloc(handleInfoSize);

	/* NtQuerySystemInformation won't give us the correct buffer size,
	   so we guess by doubling the buffer size. */
	while ((status = NtQuerySystemInformation(
			SystemHandleInformation,
			handleInfo,
			handleInfoSize,
			NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION) realloc(handleInfo, handleInfoSize *= 2);

	/* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
	if (!NT_SUCCESS(status)) {
		printf("NtQuerySystemInformation failed!\n");
		return ret;
	}

	for (i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;

		/* Check if this handle belongs to the PID the user specified. */
		if (handle.ProcessId != pid)
			continue;
		dupHandle = (HANDLE) handle.Handle;
		objectTypeInfo = (POBJECT_TYPE_INFORMATION) malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
				dupHandle,
				ObjectTypeInformation,
				objectTypeInfo,
				0x1000,
				NULL
		))) {
//			printf("[%#x] Error!\n", handle.Handle);
//			CloseHandle(dupHandle);
			continue;
		}

		/* Query the object name (unless it has an access of
		   0x0012019f, on which NtQueryObject could hang. */
		if (handle.GrantedAccess == 0x0012019f) {
			free(objectTypeInfo);
			continue;
		}

		objectNameInfo = malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
				dupHandle,
				ObjectNameInformation,
				objectNameInfo,
				0x1000,
				&returnLength
		))) {
			/* Reallocate the buffer and try again. */
			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (!NT_SUCCESS(NtQueryObject(
					dupHandle,
					ObjectNameInformation,
					objectNameInfo,
					returnLength,
					NULL
			))) {
				free(objectTypeInfo);
				free(objectNameInfo);
				continue;
			}
		}

		objectName = *(PUNICODE_STRING) objectNameInfo;
		if (objectName.Length) {
			char typename[MAX_PATH];
			sprintf_s(typename, MAX_PATH, "%.*S", objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer);
			if (!strcmp(typename, "Semaphore")) {
				char semaphore[MAX_PATH];
				sprintf_s(semaphore, MAX_PATH, "%.*S", objectName.Length / 2, objectName.Buffer);
				if (strstr(semaphore, "Worms Armageddon")) {
					if(CloseHandle(handle.Handle)) {
						ret = 1;
					}
				}
			}
		}
		free(objectTypeInfo);
		free(objectNameInfo);
	}
	free(handleInfo);
	CloseHandle(processHandle);
	return ret;
}