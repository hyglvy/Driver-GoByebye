#pragma once
#include <windows.h>
#include <random>
#include <memory>
#include <array>
#include <string_view>
#include <TlHelp32.h>
#include "mem_structs.hpp"
#include <tchar.h>
#include <iterator>

class memory_mgr
{
private:
	HKEY _registry_handle = nullptr;
	std::string _registry_key{ };

	std::uintptr_t _process_id = 0;
	std::uintptr_t _local_process_id = 0;
public:
	memory_mgr(const std::string_view reg_key, const std::string_view process)
	{
		auto status = RegOpenKeyExA(HKEY_CURRENT_USER, reg_key.data(), 0, KEY_ALL_ACCESS, &_registry_handle);
		HKEY hKey{};

		if (status != ERROR_SUCCESS)
		{
			HKEY pRegKey;
			LONG lRtnVal = 0;
			DWORD Disposition;

			lRtnVal = RegCreateKeyEx(
				HKEY_CURRENT_USER,
				_TEXT(reg_key.data()),
				0,
				NULL,
				REG_OPTION_VOLATILE,
				KEY_ALL_ACCESS,
				NULL,
				&pRegKey,
				&Disposition);

			if (lRtnVal != ERROR_SUCCESS) return;

			RegCloseKey(pRegKey);

			status = RegOpenKeyExA(HKEY_CURRENT_USER, reg_key.data(), 0, KEY_ALL_ACCESS, &_registry_handle);
			if (status != ERROR_SUCCESS)
			{
				MessageBoxA(0, E("Failed to load driver. Exiting..."), E("Error"), MB_ICONERROR | MB_OK);
				exit(0);
				return;
			}
		}

		std::generate_n(std::back_inserter(_registry_key), 16, []()
			{
				thread_local std::mt19937_64 mersenne_generator(std::random_device{ }());
				const std::uniform_int_distribution<> distribution(97, 122);
				return static_cast<std::uint8_t>(distribution(mersenne_generator));
			});

		const std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)> snap_shot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &CloseHandle);

		if (!snap_shot.get())
			return;

		PROCESSENTRY32 entry
		{
			sizeof(PROCESSENTRY32)
		};

		for (Process32First(snap_shot.get(), &entry); Process32Next(snap_shot.get(), &entry); )
			if (!std::strcmp(process.data(), entry.szExeFile))
				_process_id = static_cast<std::uintptr_t>(entry.th32ProcessID);

		_local_process_id = static_cast<std::uintptr_t>(GetCurrentProcessId());
	}

	void run(operation& request) const
	{
		operation_command command_request
		{
			_local_process_id,
			_process_id,
			secret_key,
			E("\\??\\C:\\test.exe"),
			request,
			reinterpret_cast<std::uintptr_t>(&request)
		};

		RegSetValueExA(_registry_handle, _registry_key.c_str(), 0, REG_BINARY, reinterpret_cast<std::uint8_t*>(&command_request), sizeof(command_request));
	}

	template <typename T = std::uintptr_t> T read(const std::uintptr_t address)
	{
		T buffer{ };

		operation request
		{
			address, //virtual address
			sizeof(T), //size
			reinterpret_cast<std::uintptr_t>(&buffer), //buffer
			0, //new protection
			0, //old protection
			E(""), //specific module
			operation_read
		};

		this->run(request);

		return buffer;
	}

	void read(const std::uintptr_t address, void* buffer, std::size_t size)
	{
		operation request
		{
			address, //virtual address
			size, //size
			reinterpret_cast<std::uintptr_t>(buffer), //buffer
			0, //new protection
			0, //old protection
			E(""), //specific module
			operation_read
		};

		this->run(request);
	}

	template <typename T> void write(const std::uintptr_t address, T data)
	{
		operation request
		{
			address, //virtual address
			sizeof(T), //size
			reinterpret_cast<std::uintptr_t>(&data), //buffer
			0, //new protection
			0, //old protection
			E(""), //specific module
			operation_write
		};

		this->run(request);
	}

	void write(std::uintptr_t address, void* buffer, std::size_t size) const
	{
		operation request
		{
			address, //virtual address
			size, //size
			reinterpret_cast<std::uintptr_t>(buffer), //buffer
			0, //new protection
			0, //old protection
			E(""), //specific module
			operation_write
		};

		this->run(request);
	}

	std::uintptr_t base_address() const
	{
		operation request
		{
			0, // virtual address
			0, // size
			0, // buffer
			0, // new protection
			0, // old_protection
			E(""), //specific module
			operation_base
		};

		this->run(request);

		return request.buffer;
	}

	std::uintptr_t find_signature(const std::uintptr_t base_address, const char* sig, const char* mask)
	{
		const auto buffer = std::make_unique<std::array<std::uint8_t, 0x100000>>();
		auto data = buffer.get()->data();
		std::uintptr_t result = 0;

		for (std::uintptr_t i = 0u; i < (2u << 25u); ++i)
		{
			read(base_address + i * 0x100000, data, 0x100000);

			if (!data)
				return 0;

			for (std::uintptr_t j = 0; j < 0x100000u; ++j)
			{
				if ([](std::uint8_t const* data, std::uint8_t const* sig, char const* mask)
					{
						for (; *mask; ++mask, ++data, ++sig)
						{
							if (*mask == 'x' && *data != *sig) return false;
						}
						return (*mask) == 0;
					}(data + j, (std::uint8_t*)sig, mask))
				{
					result = base_address + i * 0x100000 + j;

					std::uint32_t rel = 0;

					read(result + 3, &rel, sizeof(std::uint32_t));

					if (!rel)
						return 0;

					return result - base_address + rel + 7;
				}
			}
		}

		return 0;
	}

	std::uintptr_t find_signature_rel(const char* sig, const char* mask)
	{
		auto buffer = std::make_unique<std::array<std::uint8_t, 0x100000>>();
		auto data = buffer.get()->data();

		for (std::uintptr_t i = 0u; i < (2u << 25u); ++i)
		{
			read(this->base_address() + i * 0x100000, data, 0x100000);

			if (!data)
				return 0;

			for (std::uintptr_t j = 0; j < 0x100000u; ++j)
			{
				if ([](std::uint8_t const* data, std::uint8_t const* sig, char const* mask)
					{
						for (; *mask; ++mask, ++data, ++sig)
						{
							if (*mask == 'x' && *data != *sig) return false;
						}
						return (*mask) == 0;
					}(data + j, (std::uint8_t*)sig, mask))
				{
					return i * 0x100000 + j;
				}
			}
		}

		return 0;
	}

	std::string read_ascii(const std::uintptr_t address, std::size_t size)
	{
		std::unique_ptr<char[]> buffer(new char[size]);
		read(address, buffer.get(), size);
		return std::string(buffer.get());
	}

	std::wstring read_unicode(const std::uintptr_t address, std::size_t size)
	{
		const auto buffer = std::make_unique<wchar_t[]>(size);
		read(address, buffer.get(), size * 2);
		return std::wstring(buffer.get());
	}

	~memory_mgr()
	{
		_registry_key.clear(); _registry_key.shrink_to_fit(); _process_id = 0; CloseHandle(_registry_handle);
	}
};