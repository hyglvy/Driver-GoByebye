#pragma once
#include <mutex>
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>

namespace th = std::this_thread;
namespace ch = std::chrono;

namespace impl
{
	inline std::unique_ptr<memory_mgr> memory = nullptr;
	inline uintptr_t c_base = 0;
}