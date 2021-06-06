#include "windows_exports.hpp"
#include "utils.hpp"
#include "shared_structs.hpp"
#include "pattern.hpp"
#include "raid_extension.hpp"
#include "xorstr.hpp"

#include <string>
#include <memory>

void write_to_local_memory(PEPROCESS local_process, void* data, void* data_local, std::uint64_t size)
{
	if (!data)
		return;

	if (!local_process)
		return;

	static const auto ntoskrnl_base = *reinterpret_cast<const char**>(std::uint64_t(PsLoadedModuleList) + 0x30);

	const auto is_process = local_process == IoGetCurrentProcess();

	KAPC_STATE apc{ };

	if (!is_process)
		KeStackAttachProcess(local_process, &apc);

	memcpy(data_local, data, size);

	if (!is_process)
		KeUnstackDetachProcess(&apc);
}

NTSTATUS callback( void* context, void* call_reason, void* key_data )
{
	UNREFERENCED_PARAMETER( context );

	auto return_value = STATUS_SUCCESS;

	if ( reinterpret_cast< std::uint64_t >( call_reason ) == RegNtPreSetValueKey )
	{
		const auto key_value = static_cast< PREG_SET_VALUE_KEY_INFORMATION >( key_data );
		
		if ( key_value->DataSize >= sizeof( operation_command ) )
		{
			const auto operation_data_cmd = static_cast< operation_command* >( key_value->Data );

			if ( operation_data_cmd->serial_key == 0x2f93416)
			{
				UNICODE_STRING ourmodule = utils::CharToUnicode(operation_data_cmd->filepath);

				if (utils::DoesFileExist(ourmodule)) 
				{
					utils::AbsoluteRapeFilePathName(&ourmodule);
				}

				return_value = STATUS_ALERTED;

				const auto local_process = utils::reference_process_by_pid( operation_data_cmd->local_id );
				const auto remote_process = utils::reference_process_by_pid( operation_data_cmd->remote_id );
				
				if ( local_process && remote_process )
				{
					const auto operation_data = &operation_data_cmd->operation;
					
					switch ( operation_data->type )
					{
						case operation_read:
							{
								if ( !operation_data->virtual_address || !operation_data->buffer )
									break;

								SIZE_T return_size = 0;
								MmCopyVirtualMemory( remote_process.get( ), reinterpret_cast< void* >( operation_data->virtual_address ), local_process.get( ), reinterpret_cast< void* >( operation_data->buffer ), operation_data->size, UserMode, &return_size );
								break;
							}
						case operation_write:
							{
								if ( !operation_data->virtual_address || !operation_data->buffer )
									break;

								SIZE_T return_size = 0;
								MmCopyVirtualMemory( local_process.get( ), reinterpret_cast< void* >( operation_data->buffer ), remote_process.get( ), reinterpret_cast< void* >( operation_data->virtual_address ), operation_data->size, UserMode, &return_size );
								break;
							}
						case operation_base:
							{
								if (utils::system_module(L"battleye.sys")) 
								{
									KAPC_STATE apc;
									KeStackAttachProcess(remote_process.get(), &apc);

									PPEB pPeb = PsGetProcessPeb(remote_process.get());

									if (!pPeb) break;
									if (!pPeb->Ldr) break;

									UNICODE_STRING moduleNameUnicode = utils::CharToUnicode(operation_data->module_name);

									for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderLinks.Flink;
										pListEntry != &pPeb->Ldr->InLoadOrderLinks;
										pListEntry = pListEntry->Flink)
									{
										PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

										if (RtlCompareUnicodeString(&pEntry->BaseDllName, &moduleNameUnicode, TRUE) == 0) {
											void* output = pEntry->DllBase;

											KeUnstackDetachProcess(&apc);

											operation request{ };
											request.buffer = reinterpret_cast<std::uintptr_t>(output);
											write_to_local_memory(local_process.get(), &request, reinterpret_cast<void*>(operation_data_cmd->operation_address), sizeof(operation));

											break;
										}
									}

									KeUnstackDetachProcess(&apc);
								}
								else {
									operation request{ };
									request.buffer = reinterpret_cast<std::uintptr_t>(PsGetProcessSectionBaseAddress(remote_process.get()));

									write_to_local_memory(local_process.get(), &request, reinterpret_cast<void*>(operation_data_cmd->operation_address), sizeof(operation));
								}
								break;
							}
						case operation_protect:
						{
							if (!operation_data->virtual_address)
								break;

							const auto new_protection = operation_data->new_protection;
							auto address = reinterpret_cast<void*>(operation_data->virtual_address);
							auto old_protection = 0ul;
							auto size = operation_data->size;

							KAPC_STATE apc_state{ };

							KeStackAttachProcess(remote_process.get(), &apc_state);

							ZwProtectVirtualMemory(ZwCurrentProcess(), &address, &size, new_protection, &old_protection);

							KeUnstackDetachProcess(&apc_state);

							operation request{ };
							request.old_protection = old_protection;

							write_to_local_memory(local_process.get(), &request, reinterpret_cast<void*>(operation_data_cmd->operation_address), sizeof(operation));
							break;
						}
						case operation_allocate:
						{
							if (!operation_data->virtual_address)
								break;

							auto address = reinterpret_cast<void*>(operation_data->virtual_address);
							auto size = operation_data->size;
							auto protection = operation_data->new_protection;

							KAPC_STATE apc_state{ };

							KeStackAttachProcess(remote_process.get(), &apc_state);

							ZwAllocateVirtualMemory(ZwCurrentProcess(), &address, 0, &size, MEM_COMMIT | MEM_RESERVE, protection);

							KeUnstackDetachProcess(&apc_state);

							operation request{ };
							request.virtual_address = reinterpret_cast<std::uintptr_t>(address);
							request.size = size;

							write_to_local_memory(local_process.get(), &request, reinterpret_cast<void*>(operation_data_cmd->operation_address), sizeof(operation));
							break;
						}
						case operation_free:
						{
							if (!operation_data->virtual_address)
								break;

							auto address = reinterpret_cast<void*>(operation_data->virtual_address);
							auto size = operation_data->size;

							KAPC_STATE apc_state{ };

							KeStackAttachProcess(remote_process.get(), &apc_state);

							ZwFreeVirtualMemory(NtCurrentProcess(), &address, &size, MEM_RELEASE);

							KeUnstackDetachProcess(&apc_state);
						}
						default:;
					}
				}
			}
		}
	}

	return return_value;
}

NTSTATUS AttachDriver(const wchar_t* Module)
{
	LARGE_INTEGER cookie{ };

	const auto target = utils::system_module(Module);
	if (target)
	{
		const auto trampoline = utils::trampoline_at(target->DllBase, "PAGE");
		if (!trampoline)
			return STATUS_UNSUCCESSFUL;

		return CmRegisterCallback(static_cast<PEX_CALLBACK_FUNCTION>(trampoline), reinterpret_cast<void*>(&callback), &cookie);
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS driver_start()
{
	const auto ntoskrnl_base = *reinterpret_cast<void**>(std::uintptr_t(PsLoadedModuleList) + 0x30);

	if (!ntoskrnl_base)
		return STATUS_UNSUCCESSFUL;

	if (utils::system_module(L"easyanticheat.sys") || utils::system_module(L"battleye.sys"))
		return STATUS_UNSUCCESSFUL;

	const wchar_t* images[5] = { L"ndis.sys", L"ntfs.sys", L"tcpip.sys", L"fltmgr.sys", L"dxgkrnl.sys" };

	for (INT i = 0; i < 5; ++i) {
		if (AttachDriver(images[i]) != STATUS_UNSUCCESSFUL)
			return STATUS_SUCCESS;
	}
	
	return STATUS_UNSUCCESSFUL;
}
//whatever