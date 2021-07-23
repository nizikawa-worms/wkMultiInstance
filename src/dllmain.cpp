#include <windows.h>
#include <exception>
#include <string>
#include <MinHook.h>
#include <stdexcept>
#include <algorithm>
#include <set>
#include <mutex>
#include <format>


int useDebugPrint = 0;
#define debugf(fmt, ...) if(useDebugPrint) printf("%s:%d: " fmt, __func__ , __LINE__, __VA_ARGS__);

extern "C" {
int FindAndCloseWAHandle();
}

std::set<std::string> hookfiles = {
		"data\\current.thm",
		"data\\landgen.svg",
		"data\\temp.thm",
		"data\\land.dat",
		"data/land.dat",
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

std::string fileHook(const char *lpFileName, bool insert=true) {
	std::string name(lpFileName);
	if (hookfiles.find(name) != hookfiles.end()) {
		static std::string prefix;
		static std::once_flag flag;
		std::call_once(flag, [&](){
			char buff[MAX_PATH];
			GetTempPathA(sizeof(buff), buff);
			prefix = std::format("{}\\WA-{}.", buff, GetCurrentProcessId());
		});
		debugf("fileHook: |%s|\n", name.c_str());
		std::replace(name.begin(), name.end(), '\\','_');
		std::replace(name.begin(), name.end(), '/','_');
		name = prefix + name;
		debugf("\t-> |%s|\n", name.c_str());
		if(insert) tmpfiles.insert(name);
	}
	return name;
}

HANDLE (WINAPI *origCreateFileA)(_In_ LPCSTR lpFileName,
		_In_ DWORD dwDesiredAccess,
		_In_ DWORD dwShareMode,
		_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_In_ DWORD dwCreationDisposition,
		_In_ DWORD dwFlagsAndAttributes,
		_In_opt_ HANDLE hTemplateFile
);

HANDLE WINAPI hookCreateFileA(
		_In_ LPCSTR lpFileName,
		_In_ DWORD dwDesiredAccess,
		_In_ DWORD dwShareMode,
		_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_In_ DWORD dwCreationDisposition,
		_In_ DWORD dwFlagsAndAttributes,
		_In_opt_ HANDLE hTemplateFile
) {
	debugf("|%s|\n", lpFileName);
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
	debugf("|%s|\n", lpFileName);
	auto file = fileHook(lpFileName);
	return origFindFirstFileA(file.c_str(), lpFindFileData);
}

BOOL (WINAPI *origMoveFileA)(
		_In_ LPCSTR lpExistingFileName,
		_In_ LPCSTR lpNewFileName
);

BOOL WINAPI hookMoveFileA(
		_In_ LPCSTR lpExistingFileName,
		_In_ LPCSTR lpNewFileName
) {
	debugf("1: |%s| 2: |%s|\n", lpExistingFileName, lpNewFileName);
	auto file1 = fileHook(lpExistingFileName, false);
	auto file2 = fileHook(lpNewFileName);
	return origMoveFileA(file1.c_str(), file2.c_str());
}

BOOL (WINAPI *origDeleteFileA)(
		_In_ LPCSTR lpFileName
);

BOOL WINAPI hookDeleteFileA(
		_In_ LPCSTR lpFileName
) {
	debugf("|%s|\n", lpFileName);
	auto file = fileHook(lpFileName, false);
	return origDeleteFileA(file.c_str());
}



HWND (WINAPI *origCreateWindowExA)(
		_In_ DWORD dwExStyle,
		_In_opt_ LPCSTR lpClassName,
		_In_opt_ LPCSTR lpWindowName,
		_In_ DWORD dwStyle,
		_In_ int X,
		_In_ int Y,
		_In_ int nWidth,
		_In_ int nHeight,
		_In_opt_ HWND hWndParent,
		_In_opt_ HMENU hMenu,
		_In_opt_ HINSTANCE hInstance,
		_In_opt_ LPVOID lpParam);

HWND WINAPI hookCreateWindowExA(
		_In_ DWORD dwExStyle,
		_In_opt_ LPCSTR lpClassName,
		_In_opt_ LPCSTR lpWindowName,
		_In_ DWORD dwStyle,
		_In_ int X,
		_In_ int Y,
		_In_ int nWidth,
		_In_ int nHeight,
		_In_opt_ HWND hWndParent,
		_In_opt_ HMENU hMenu,
		_In_opt_ HINSTANCE hInstance,
		_In_opt_ LPVOID lpParam) {

	if(dwExStyle &= WS_EX_APPWINDOW) {
		std::string name = std::format("{} [{}]", lpWindowName, GetCurrentProcessId());
		return origCreateWindowExA(dwExStyle, lpClassName, name.c_str(), dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
	} else {
		return origCreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
	}
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH:
			try {
				char iniFile[] = ".\\wkMultiInstance.ini";
				int moduleEnabled = GetPrivateProfileIntA("general", "EnableModule", 1, iniFile);
				if(!moduleEnabled) return TRUE;

				int hookFiles = GetPrivateProfileIntA("general", "HookFileAccess", 1, iniFile);
				int renameWindow = GetPrivateProfileIntA("general", "RenameWindow", 1, iniFile);
				useDebugPrint = GetPrivateProfileIntA("general", "UseDebugPrint", 0, iniFile);

				if(!FindAndCloseWAHandle())
					throw std::runtime_error("Failed to release WA semaphore");
				if (MH_Initialize() != MH_OK)
					throw std::runtime_error("Failed to initialize MinHook");
				if(hookFiles) {
					if (MH_CreateHookApi(L"kernel32.dll", "CreateFileA", &hookCreateFileA, reinterpret_cast<LPVOID *>(&origCreateFileA)) != MH_OK)
						throw std::runtime_error("Failed to create hook (CreateFileA)");
					if (MH_CreateHookApi(L"kernel32.dll", "FindFirstFileA", &hookFindFirstFileA, reinterpret_cast<LPVOID *>(&origFindFirstFileA)) != MH_OK)
						throw std::runtime_error("Failed to create hook (FindFirstFileA)");
					if (MH_CreateHookApi(L"kernel32.dll", "MoveFileA", &hookMoveFileA, reinterpret_cast<LPVOID *>(&origMoveFileA)) != MH_OK)
						throw std::runtime_error("Failed to create hook (MoveFileA)");
					if (MH_CreateHookApi(L"kernel32.dll", "DeleteFileA", &hookDeleteFileA, reinterpret_cast<LPVOID *>(&origDeleteFileA)) != MH_OK)
						throw std::runtime_error("Failed to create hook (DeleteFileA)");
				}
				if(renameWindow) {
					if (MH_CreateHookApi(L"user32.dll", "CreateWindowExA", &hookCreateWindowExA, reinterpret_cast<LPVOID *>(&origCreateWindowExA)) != MH_OK)
						throw std::runtime_error("Failed to create hook (CreateWindowExA)");
				}
				if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
					throw std::runtime_error("Failed to enable hooks");
			} catch (std::exception &e) {
				MessageBoxA(0, e.what(), "wkMultiInstance v1.1.0 (" __DATE__ " " __TIME__ ")", MB_ICONERROR);
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
