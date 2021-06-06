#pragma once
#include <tuple>
#include <random>
#include <cstdint>
#include <memory>
#include "windows_exports.hpp"
#include "pattern.hpp"
#include "xorstr.hpp"
#include <cstdarg>

using process_reference = std::unique_ptr<std::remove_pointer_t<PEPROCESS>, decltype( &ObfDereferenceObject )>;
using driver_reference = std::unique_ptr<std::remove_pointer_t<PDRIVER_OBJECT>, decltype( &ObfDereferenceObject )>;

namespace utils
{
	PLDR_DATA_TABLE_ENTRY system_module( const wchar_t* module_name )
	{
		static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );

		UNICODE_STRING unicode_string{ };
		RtlInitUnicodeString( &unicode_string, module_name );

		PLDR_DATA_TABLE_ENTRY system_module_entry = nullptr;

		for ( auto entry = PsLoadedModuleList; entry != PsLoadedModuleList->Blink; entry = entry->Flink )
		{
			PLDR_DATA_TABLE_ENTRY data_table = CONTAINING_RECORD( entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

			if ( RtlEqualUnicodeString( &data_table->BaseDllName, &unicode_string, TRUE ) )
			{
				system_module_entry = data_table;
				break;
			}
		}

		return system_module_entry;
	}

	void* system_routine( const wchar_t* routine_name )
	{
		static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );

		UNICODE_STRING unicode_string{ };
		RtlInitUnicodeString( &unicode_string, routine_name );

		return MmGetSystemRoutineAddress( &unicode_string );
	}

	void* system_export( const wchar_t* module_name, const char* export_name )
	{
		static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );

		const auto module = system_module( module_name );

		if ( !module )
			return nullptr;

		return RtlFindExportedRoutineByName( module->DllBase, export_name );
	}

	inline auto is_specific_section(IMAGE_SECTION_HEADER section, const char* target) -> bool
	{
		if (_stricmp(reinterpret_cast<const char*>(section.Name), target) == 0)
		{
			return true;
		}

		return false;
	}

	NTSTATUS AbsoluteRapeFilePathName(PUNICODE_STRING pUsDriverPath)
	{
		IO_STATUS_BLOCK IoStatusBlock;
		HANDLE FileHandle;
		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(
			&ObjectAttributes,
			pUsDriverPath,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			0,
			0);

		NTSTATUS Status = IoCreateFileEx(&FileHandle,
			SYNCHRONIZE | DELETE,
			&ObjectAttributes,
			&IoStatusBlock,
			nullptr,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			nullptr,
			0,
			CreateFileTypeNone,
			nullptr,
			IO_NO_PARAMETER_CHECKING,
			nullptr);

		if (!NT_SUCCESS(Status)) { return Status; }

		PFILE_OBJECT FileObject;
		Status = ObReferenceObjectByHandleWithTag(FileHandle,
			SYNCHRONIZE | DELETE,
			*IoFileObjectType,
			KernelMode,
			POOL_TAG_USE,
			reinterpret_cast<PVOID*>(&FileObject),
			nullptr);

		if (!NT_SUCCESS(Status))
		{
			ObCloseHandle(FileHandle, KernelMode);
			return Status;
		}
		
		const PSECTION_OBJECT_POINTERS SectionObjectPointer = FileObject->SectionObjectPointer;
		SectionObjectPointer->ImageSectionObject = nullptr;
		
		CONST BOOLEAN ImageSectionFlushed = MmFlushImageSection(SectionObjectPointer, MmFlushForDelete);
		
		ObfDereferenceObject(FileObject);
		ObCloseHandle(FileHandle, KernelMode);

		if (ImageSectionFlushed)
		{
			Status = ZwDeleteFile(&ObjectAttributes);
			if (NT_SUCCESS(Status))
			{
				return Status;
			}
		}
		return Status;
	}

	BOOLEAN DoesFileExist(UNICODE_STRING path) 
	{
		HANDLE   handle;
		NTSTATUS ntstatus;
		IO_STATUS_BLOCK    ioStatusBlock;
		OBJECT_ATTRIBUTES  objAttr;

		InitializeObjectAttributes(&objAttr, &path,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);

		ntstatus = ZwOpenFile(&handle, GENERIC_READ, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL);
		if (ntstatus == STATUS_SUCCESS && handle != NULL) {
			ZwClose(handle);
			return TRUE;
		}
		return FALSE;
	}

	inline auto CharToUnicode(const char* path) -> UNICODE_STRING
	{
		UNICODE_STRING Module;
		ANSI_STRING AS;

		RtlInitAnsiString(&AS, path);
		RtlAnsiStringToUnicodeString(&Module, &AS, TRUE);
		return Module;
	}

	void* trampoline_at(void* base_address, const char* target)
	{
		static const auto ntoskrnl_base = *reinterpret_cast<const char**>(std::uintptr_t(PsLoadedModuleList) + 0x30);

		const auto nt_header = RtlImageNtHeader(base_address);

		if (!nt_header)
			return nullptr;

		const auto section_array = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_header + 1);

		for (auto section = 0; section < nt_header->FileHeader.NumberOfSections; section++)
		{
			const auto current = section_array[section];

			if (current.VirtualAddress == 0 || current.Misc.VirtualSize == 0)
				continue;

			if (!(is_specific_section(current, target)))
				continue;
			
			const auto section_address = reinterpret_cast<char*>(base_address) + current.VirtualAddress;

			for (auto i = section_address; i < (section_address + current.SizeOfRawData) - 1; ++i)
			{
				if (!i)
					continue;

				if (*reinterpret_cast<std::uint16_t*>(i) == 0xe1ff) {
					return i;
				}
			}
		}
		return nullptr;
	}

	process_reference reference_process_by_pid( std::uintptr_t pid)
	{
		static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );

		PEPROCESS process{ };

		if ( !NT_SUCCESS( PsLookupProcessByProcessId( reinterpret_cast< HANDLE >( pid ), &process ) ) )
			return process_reference(nullptr, nullptr);

		return process_reference( process, &ObfDereferenceObject );
	}

	driver_reference reference_driver_by_name( const wchar_t* driver_name )
	{
		static const auto ntoskrnl_base = *reinterpret_cast< const char** >( std::uintptr_t( PsLoadedModuleList ) + 0x30 );

		UNICODE_STRING driver_unicode{ };
		RtlInitUnicodeString( &driver_unicode, driver_name );

		PDRIVER_OBJECT driver_local = nullptr;
		ObReferenceObjectByName( &driver_unicode, OBJ_CASE_INSENSITIVE, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, reinterpret_cast< void** >( &driver_local ) );

		return driver_reference( driver_local, &ObfDereferenceObject );
	}
}