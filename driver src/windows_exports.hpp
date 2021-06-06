#pragma once
#include <ntifs.h>
#include <cstdint>

#undef ExFreePool
#define POOL_TAG_USE 'xItp'
#define ExFreePool(a) ExFreePoolWithTag (a, POOL_TAG_USE)

typedef unsigned char       BYTE;
typedef unsigned long long QWORD;

typedef struct _IMAGE_FILE_HEADER
{
	USHORT Machine;
	USHORT NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
	ULONG VirtualAddress;
	ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_SECTION_HEADER
{
	UCHAR  Name[ 8 ];
	union
	{
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT NumberOfRelocations;
	USHORT NumberOfLinenumbers;
	ULONG Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
	USHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	ULONG SizeOfCode;
	ULONG SizeOfInitializedData;
	ULONG SizeOfUninitializedData;
	ULONG AddressOfEntryPoint;
	ULONG BaseOfCode;
	ULONGLONG ImageBase;
	ULONG SectionAlignment;
	ULONG FileAlignment;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	USHORT MajorImageVersion;
	USHORT MinorImageVersion;
	USHORT MajorSubsystemVersion;
	USHORT MinorSubsystemVersion;
	ULONG Win32VersionValue;
	ULONG SizeOfImage;
	ULONG SizeOfHeaders;
	ULONG CheckSum;
	USHORT Subsystem;
	USHORT DllCharacteristics;
	ULONGLONG SizeOfStackReserve;
	ULONGLONG SizeOfStackCommit;
	ULONGLONG SizeOfHeapReserve;
	ULONGLONG SizeOfHeapCommit;
	ULONG LoaderFlags;
	ULONG NumberOfRvaAndSizes;
	struct _IMAGE_DATA_DIRECTORY DataDirectory[ 16 ];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64
{
	ULONG Signature;
	struct _IMAGE_FILE_HEADER FileHeader;
	struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

//
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	unsigned int Length;
	int Initialized;
	void* SSHandle;
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB64
{
	unsigned char InheritedAddressSpace;
	unsigned char ReadImageFileExecOptions;
	unsigned char BeingDebugged;
	unsigned char BitField;
	unsigned char pad_0x0004[ 0x4 ];
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;	
} PEB64, * PPEB64;

struct PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[ 16 ];
};

#define near
typedef unsigned char near* PBYTE;

	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation,				   // q: SYSTEM_BASIC_INFORMATION
		SystemProcessorInformation,			   // q: SYSTEM_PROCESSOR_INFORMATION
		SystemPerformanceInformation,		   // q: SYSTEM_PERFORMANCE_INFORMATION
		SystemTimeOfDayInformation,			   // q: SYSTEM_TIMEOFDAY_INFORMATION
		SystemPathInformation,				   // not implemented
		SystemProcessInformation,			   // q: SYSTEM_PROCESS_INFORMATION
		SystemCallCountInformation,			   // q: SYSTEM_CALL_COUNT_INFORMATION
		SystemDeviceInformation,			   // q: SYSTEM_DEVICE_INFORMATION
		SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
		SystemFlagsInformation,				   // q: SYSTEM_FLAGS_INFORMATION
		SystemCallTimeInformation,			   // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
		SystemModuleInformation,			   // q: RTL_PROCESS_MODULES
		SystemLocksInformation,				   // q: SYSTEM_LOCK_INFORMATION
		SystemStackTraceInformation,
		SystemPagedPoolInformation,			   // not implemented
		SystemNonPagedPoolInformation,		   // not implemented
		SystemHandleInformation,			   // q: SYSTEM_HANDLE_INFORMATION
		SystemObjectInformation,			   // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
		SystemPageFileInformation,			   // q: SYSTEM_PAGEFILE_INFORMATION
		SystemVdmInstemulInformation,		   // q
		SystemVdmBopInformation,			   // not implemented // 20
		SystemFileCacheInformation,			   // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
		SystemPoolTagInformation,			   // q: SYSTEM_POOLTAG_INFORMATION
		SystemInterruptInformation,			   // q: SYSTEM_INTERRUPT_INFORMATION
		SystemDpcBehaviorInformation,		   // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
		SystemFullMemoryInformation,		   // not implemented
		SystemLoadGdiDriverInformation,		   // s (kernel-mode only)
		SystemUnloadGdiDriverInformation,	  // s (kernel-mode only)
		SystemTimeAdjustmentInformation,	   // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
		SystemSummaryMemoryInformation,		   // not implemented
		SystemMirrorMemoryInformation,		   // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
		SystemPerformanceTraceInformation,	 // s
		SystemObsolete0,					   // not implemented
		SystemExceptionInformation,			   // q: SYSTEM_EXCEPTION_INFORMATION
		SystemCrashDumpStateInformation,	   // s (requires SeDebugPrivilege)
		SystemKernelDebuggerInformation,	   // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
		SystemContextSwitchInformation,		   // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
		SystemRegistryQuotaInformation,		   // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
		SystemExtendServiceTableInformation,   // s (requires SeLoadDriverPrivilege) // loads win32k only
		SystemPrioritySeperation,			   // s (requires SeTcbPrivilege)
		SystemVerifierAddDriverInformation,	// s (requires SeDebugPrivilege) // 40
		SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
		SystemProcessorIdleInformation,		   // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
		SystemLegacyDriverInformation,		   // q: SYSTEM_LEGACY_DRIVER_INFORMATION
		SystemCurrentTimeZoneInformation,	  // q
		SystemLookasideInformation,			   // q: SYSTEM_LOOKASIDE_INFORMATION
		SystemTimeSlipNotification,			   // s (requires SeSystemtimePrivilege)
		SystemSessionCreate,				   // not implemented
		SystemSessionDetach,				   // not implemented
		SystemSessionInformation,			   // not implemented
		SystemRangeStartInformation,		   // q: SYSTEM_RANGE_START_INFORMATION // 50
		SystemVerifierInformation,			   // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
		SystemVerifierThunkExtend,			   // s (kernel-mode only)
		SystemSessionProcessInformation,	   // q: SYSTEM_SESSION_PROCESS_INFORMATION
		SystemLoadGdiDriverInSystemSpace,	  // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
		SystemNumaProcessorMap,				   // q
		SystemPrefetcherInformation,		   // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
		SystemExtendedProcessInformation,	  // q: SYSTEM_PROCESS_INFORMATION
		SystemRecommendedSharedDataAlignment,  // q
		SystemComPlusPackage,				   // q; s
		SystemNumaAvailableMemory,			   // 60
		SystemProcessorPowerInformation,	   // q: SYSTEM_PROCESSOR_POWER_INFORMATION
		SystemEmulationBasicInformation,	   // q
		SystemEmulationProcessorInformation,
		SystemExtendedHandleInformation,			   // q: SYSTEM_HANDLE_INFORMATION_EX
		SystemLostDelayedWriteInformation,			   // q: ULONG
		SystemBigPoolInformation,					   // q: SYSTEM_BIGPOOL_INFORMATION
		SystemSessionPoolTagInformation,			   // q: SYSTEM_SESSION_POOLTAG_INFORMATION
		SystemSessionMappedViewInformation,			   // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
		SystemHotpatchInformation,					   // q; s
		SystemObjectSecurityMode,					   // q // 70
		SystemWatchdogTimerHandler,					   // s (kernel-mode only)
		SystemWatchdogTimerInformation,				   // q (kernel-mode only); s (kernel-mode only)
		SystemLogicalProcessorInformation,			   // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
		SystemWow64SharedInformationObsolete,		   // not implemented
		SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
		SystemFirmwareTableInformation,				   // SYSTEM_FIRMWARE_TABLE_INFORMATION
		SystemModuleInformationEx,					   // q: RTL_PROCESS_MODULE_INFORMATION_EX
		SystemVerifierTriageInformation,			   // not implemented
		SystemSuperfetchInformation,				   // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
		SystemMemoryListInformation,				   // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
		SystemFileCacheInformationEx,				   // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
		SystemThreadPriorityClientIdInformation,	   // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
		SystemProcessorIdleCycleTimeInformation,	   // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
		SystemVerifierCancellationInformation,		   // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
		SystemProcessorPowerInformationEx,			   // not implemented
		SystemRefTraceInformation,					   // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
		SystemSpecialPoolInformation,				   // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
		SystemProcessIdInformation,					   // q: SYSTEM_PROCESS_ID_INFORMATION
		SystemErrorPortInformation,					   // s (requires SeTcbPrivilege)
		SystemBootEnvironmentInformation,			   // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
		SystemHypervisorInformation,				   // q; s (kernel-mode only)
		SystemVerifierInformationEx,				   // q; s: SYSTEM_VERIFIER_INFORMATION_EX
		SystemTimeZoneInformation,					   // s (requires SeTimeZonePrivilege)
		SystemImageFileExecutionOptionsInformation,	// s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
		SystemCoverageInformation,					   // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
		SystemPrefetchPatchInformation,				   // not implemented
		SystemVerifierFaultsInformation,			   // s (requires SeDebugPrivilege)
		SystemSystemPartitionInformation,			   // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
		SystemSystemDiskInformation,				   // q: SYSTEM_SYSTEM_DISK_INFORMATION
		SystemProcessorPerformanceDistribution,		   // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
		SystemNumaProximityNodeInformation,			   // q
		SystemDynamicTimeZoneInformation,			   // q; s (requires SeTimeZonePrivilege)
		SystemCodeIntegrityInformation,				   // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
		SystemProcessorMicrocodeUpdateInformation,	 // s
		SystemProcessorBrandString,					   // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
		SystemVirtualAddressInformation,			   // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
		SystemLogicalProcessorAndGroupInformation,	 // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
		SystemProcessorCycleTimeInformation,		   // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
		SystemStoreInformation,						   // q; s // SmQueryStoreInformation
		SystemRegistryAppendString,					   // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
		SystemAitSamplingValue,						   // s: ULONG (requires SeProfileSingleProcessPrivilege)
		SystemVhdBootInformation,					   // q: SYSTEM_VHD_BOOT_INFORMATION
		SystemCpuQuotaInformation,					   // q; s // PsQueryCpuQuotaInformation
		SystemNativeBasicInformation,				   // not implemented
		SystemSpare1,								   // not implemented
		SystemLowPriorityIoInformation,				   // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
		SystemTpmBootEntropyInformation,			   // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
		SystemVerifierCountersInformation,			   // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
		SystemPagedPoolInformationEx,				   // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
		SystemSystemPtesInformationEx,				   // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
		SystemNodeDistanceInformation,				   // q
		SystemAcpiAuditInformation,					   // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
		SystemBasicPerformanceInformation,			   // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
		SystemQueryPerformanceCounterInformation,	  // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
		SystemSessionBigPoolInformation,			   // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
		SystemBootGraphicsInformation,				   // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
		SystemScrubPhysicalMemoryInformation,
		SystemBadPageInformation,
		SystemProcessorProfileControlArea,
		SystemCombinePhysicalMemoryInformation, // 130
		SystemEntropyInterruptTimingCallback,
		SystemConsoleInformation,		 // q: SYSTEM_CONSOLE_INFORMATION
		SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION
		SystemThrottleNotificationInformation,
		SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
		SystemDeviceDataInformation,			   // q: SYSTEM_DEVICE_DATA_INFORMATION
		SystemDeviceDataEnumerationInformation,
		SystemMemoryTopologyInformation,		 // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
		SystemMemoryChannelInformation,			 // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
		SystemBootLogoInformation,				 // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
		SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
		SystemSpare0,
		SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
		SystemPageFileInformationEx,	   // q: SYSTEM_PAGEFILE_INFORMATION_EX
		SystemSecureBootInformation,	   // q: SYSTEM_SECUREBOOT_INFORMATION
		SystemEntropyInterruptTimingRawInformation,
		SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
		SystemFullProcessInformation,				   // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
		SystemKernelDebuggerInformationEx,			   // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
		SystemBootMetadataInformation,				   // 150
		SystemSoftRebootInformation,
		SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
		SystemOfflineDumpConfigInformation,
		SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
		SystemRegistryReconciliationInformation,
		SystemEdidInformation,
		SystemManufacturingInformation,			 // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
		SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
		SystemHypervisorDetailInformation,		 // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
		SystemProcessorCycleStatsInformation,	// q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
		SystemVmGenerationCountInformation,
		SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
		SystemKernelDebuggerFlags,
		SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
		SystemIsolatedUserModeInformation,	// q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
		SystemHardwareSecurityTestInterfaceResultsInformation,
		SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
		SystemAllowedCpuSetsInformation,
		SystemDmaProtectionInformation,		   // q: SYSTEM_DMA_PROTECTION_INFORMATION
		SystemInterruptCpuSetsInformation,	 // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
		SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
		SystemCodeIntegrityPolicyFullInformation,
		SystemAffinitizedInterruptProcessorInformation,
		SystemRootSiloInformation,  // q: SYSTEM_ROOT_SILO_INFORMATION
		SystemCpuSetInformation,	// q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
		SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
		SystemWin32WerStartCallout,
		SystemSecureKernelProfileInformation,			// q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
		SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
		SystemInterruptSteeringInformation,				// 180
		SystemSupportedProcessorArchitectures,
		SystemMemoryUsageInformation,			   // q: SYSTEM_MEMORY_USAGE_INFORMATION
		SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
		MaxSystemInfoClass
	} SYSTEM_INFORMATION_CLASS;

	/*typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		LIST_ENTRY HashLinks;
		ULONG TimeDateStamp;
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;*/

	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section; // Not filled in
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[MAXIMUM_FILENAME_LENGTH];
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _PEB32
	{
		UCHAR InheritedAddressSpace;
		UCHAR ReadImageFileExecOptions;
		UCHAR BeingDebugged;
		UCHAR BitField;
		ULONG Mutant;
		ULONG ImageBaseAddress;
		ULONG Ldr;
		ULONG ProcessParameters;
		ULONG SubSystemData;
		ULONG ProcessHeap;
		ULONG FastPebLock;
		ULONG AtlThunkSListPtr;
		ULONG IFEOKey;
		ULONG CrossProcessFlags;
		ULONG UserSharedInfoPtr;
		ULONG SystemReserved;
		ULONG AtlThunkSListPtr32;
		ULONG ApiSetMap;
	} PEB32, * PPEB32;

	typedef struct _PEB_LDR_DATA32
	{
		ULONG Length;
		UCHAR Initialized;
		ULONG SsHandle;
		LIST_ENTRY32 InLoadOrderModuleList;
		LIST_ENTRY32 InMemoryOrderModuleList;
		LIST_ENTRY32 InInitializationOrderModuleList;
	} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

	typedef struct _LDR_DATA_TABLE_ENTRY32
	{
		LIST_ENTRY32 InLoadOrderLinks;
		LIST_ENTRY32 InMemoryOrderLinks;
		LIST_ENTRY32 InInitializationOrderLinks;
		ULONG DllBase;
		ULONG EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING32 FullDllName;
		UNICODE_STRING32 BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		LIST_ENTRY32 HashLinks;
		ULONG TimeDateStamp;
	} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

	/*typedef struct _PEB_LDR_DATA
	{
		ULONG Length;
		UCHAR Initialized;
		PVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;*/

	typedef struct _RTL_USER_PROCESS_PARAMETERS
	{
		unsigned char Reserved1[16];
		PVOID Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void); // not exported

	typedef struct _PEB
	{
		unsigned char Reserved1[2];
		unsigned char BeingDebugged;
		unsigned char Reserved2[1];
		PVOID Reserved3[2];
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID Reserved4[3];
		PVOID AtlThunkSListPtr;
		PVOID Reserved5;
		ULONG Reserved6;
		PVOID Reserved7;
		ULONG Reserved8;
		ULONG AtlThunkSListPtr32;
		PVOID Reserved9[45];
		unsigned char Reserved10[96];
		PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
		unsigned char Reserved11[128];
		PVOID Reserved12[1];
		ULONG SessionId;
	} PEB, * PPEB;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


	typedef struct _SYSTEM_MODULE
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		CHAR  FullPathName[256];
	} SYSTEM_MODULE, * PSYSTEM_MODULE;
	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG_PTR     ModuleCount;
		SYSTEM_MODULE Modules[1];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
		USHORT e_magic;                     // Magic number
		USHORT e_cblp;                      // Bytes on last page of file
		USHORT e_cp;                        // Pages in file
		USHORT e_crlc;                      // Relocations
		USHORT e_cparhdr;                   // Size of header in paragraphs
		USHORT e_minalloc;                  // Minimum extra paragraphs needed
		USHORT e_maxalloc;                  // Maximum extra paragraphs needed
		USHORT e_ss;                        // Initial (relative) SS value
		USHORT e_sp;                        // Initial SP value
		USHORT e_csum;                      // Checksum
		USHORT e_ip;                        // Initial IP value
		USHORT e_cs;                        // Initial (relative) CS value
		USHORT e_lfarlc;                    // File address of relocation table
		USHORT e_ovno;                      // Overlay number
		USHORT e_res[4];                    // Reserved words
		USHORT e_oemid;                     // OEM identifier (for e_oeminfo)
		USHORT e_oeminfo;                   // OEM information; e_oemid specific
		USHORT e_res2[10];                  // Reserved words
		LONG   e_lfanew;                    // File address of new exe header
	} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

	typedef struct _IMAGE_EXPORT_DIRECTORY {
		ULONG   Characteristics;
		ULONG   TimeDateStamp;
		USHORT  MajorVersion;
		USHORT  MinorVersion;
		ULONG   Name;
		ULONG   Base;
		ULONG   NumberOfFunctions;
		ULONG   NumberOfNames;
		ULONG   AddressOfFunctions;     // RVA from base of image
		ULONG   AddressOfNames;         // RVA from base of image
		ULONG   AddressOfNameOrdinals;  // RVA from base of image
	} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;
	
	typedef union _EX_FAST_REF
	{
		void* Object;
		struct
		{
			unsigned __int64 RefCnt : 4;
		};
		unsigned __int64 Value;
	} EX_FAST_REF, * PEX_FAST_REF;


extern "C"
{
	__declspec( dllimport ) PLIST_ENTRY NTAPI PsLoadedModuleList;
	__declspec( dllimport ) POBJECT_TYPE* IoDriverObjectType;
	__declspec( dllimport ) PVOID NTAPI RtlFindExportedRoutineByName( PVOID, PCCH );
	__declspec( dllimport ) PVOID NTAPI PsGetProcessSectionBaseAddress( PEPROCESS );
	__declspec( dllimport ) PPEB NTAPI PsGetProcessPeb( PEPROCESS );
	__declspec( dllimport ) NTSTATUS NTAPI MmCopyVirtualMemory( PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T );
	__declspec( dllimport ) NTSTATUS NTAPI ZwProtectVirtualMemory( HANDLE, PVOID*, PSIZE_T, ULONG, PULONG );
	__declspec( dllimport ) PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader( PVOID );
	__declspec( dllimport ) NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID OPTIONAL, PVOID*);
	__declspec( dllimport )
		NTSTATUS
		NTAPI
		ZwQuerySystemInformation(
			_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
			_Out_opt_ PVOID SystemInformation,
			_In_ ULONG SystemInformationLength,
			_Out_opt_ PULONG ReturnLength);
}