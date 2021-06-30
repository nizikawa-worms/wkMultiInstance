#include <windows.h>
#include <exception>
#include <string>
#include <MinHook.h>
#include <stdexcept>
#include <algorithm>
#include <set>
#include <mutex>
#include <format>

extern "C" {
int FindAndCloseWAHandle();
}

std::set<std::string> hookfiles = {
		"data\\current.thm",
		"data\\landgen.svg",
		"data\\land.dat",
		"custom.dat",
		"thm.prv",
		"w2.prv",
		"tmp.thm",
		"thumb0.dat",
		"thumb1.dat",
		"thumb2.dat",
		"thumb3.dat",
		"thumb4.dat",
		"thumb5.dat",
		"thumb6.dat",
		"thumb7.dat"
};
std::set<std::string> tmpfiles;


HANDLE (WINAPI *origCreateFileA)(
		_In_ LPCSTR lpFileName,
		_In_ DWORD dwDesiredAccess,
		_In_ DWORD dwShareMode,
		_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_In_ DWORD dwCreationDisposition,
		_In_ DWORD dwFlagsAndAttributes,
		_In_opt_ HANDLE hTemplateFile
);

std::string fileHook(const char *lpFileName) {
	std::string name(lpFileName);
	if (hookfiles.find(name) != hookfiles.end()) {
		static std::string prefix;
		static std::once_flag flag;
		std::call_once(flag, [&](){
			char buff[MAX_PATH];
			GetTempPathA(sizeof(buff), buff);
			prefix = std::format("{}\\WA-{}.", buff, GetCurrentProcessId());
		});
		std::replace(name.begin(), name.end(), '\\','_');
		name = prefix + name;
		tmpfiles.insert(name);
	}
	return name;
}

HANDLE WINAPI hookCreateFileA(
		_In_ LPCSTR lpFileName,
		_In_ DWORD dwDesiredAccess,
		_In_ DWORD dwShareMode,
		_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_In_ DWORD dwCreationDisposition,
		_In_ DWORD dwFlagsAndAttributes,
		_In_opt_ HANDLE hTemplateFile
) {
	auto file = fileHook(lpFileName);
	return origCreateFileA(file.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE (WINAPI *origFindFirstFileA)(
		_In_ LPCSTR lpFileName,
		_Out_ LPWIN32_FIND_DATAA lpFindFileData
);

HANDLE WINAPI hookFindFirstFileA(
		_In_ LPCSTR lpFileName,
		_Out_ LPWIN32_FIND_DATAA lpFindFileData
) {
	auto file = fileHook(lpFileName);
	return origFindFirstFileA(file.c_str(), lpFindFileData);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH:
			try {
				if(!FindAndCloseWAHandle())
					throw std::runtime_error("Failed to release WA semaphore");

				if (MH_Initialize() != MH_OK)
					throw std::runtime_error("Failed to initialize MinHook");
				if (MH_CreateHookApi(L"kernel32.dll", "CreateFileA", &hookCreateFileA, reinterpret_cast<LPVOID *>(&origCreateFileA)) != MH_OK)
					throw std::runtime_error("Failed to create hook (CreateFileA)");
				if (MH_CreateHookApi(L"kernel32.dll", "FindFirstFileA", &hookFindFirstFileA, reinterpret_cast<LPVOID *>(&origFindFirstFileA)) != MH_OK)
					throw std::runtime_error("Failed to create hook (FindFirstFileA)");
				if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
					throw std::runtime_error("Failed to enable hooks");
			} catch (std::exception &e) {
				MessageBoxA(0, e.what(), "wkMultiInstance v1.0.0 (" __DATE__ " " __TIME__ ")", MB_ICONERROR);
			}
			break;
		case DLL_PROCESS_DETACH:
			for (auto &file : tmpfiles) {
				_unlink(file.c_str());
			}
			tmpfiles.clear();
			break;
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		default:
			break;
	}
	return TRUE;
}
