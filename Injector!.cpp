#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <limits>

bool InjectDLL(const std::string& processName, const std::string& dllPath) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to create process snapshot!";
        return false;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        std::cerr << "Failed to get first process!";
        CloseHandle(hSnapshot);
        return false;
    }

    DWORD processId = 0;
    do {
        if (processName == pe32.szExeFile) {
            processId = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));
    CloseHandle(hSnapshot);

    if (!processId)
    {
        std::cerr << "Process not found! " << GetLastError();
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "Failed to open process! Error: " << GetLastError();
        return false;
    }

    LPVOID allocMemory = VirtualAllocEx(hProcess, NULL, dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocMemory) {
        std::cerr << "Failed to allocate memory in target process! Error: " << GetLastError();
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, allocMemory, dllPath.c_str(), dllPath.size() + 1, NULL)) {
        std::cerr << "Failed to write DLL path to target process memory! Error: " << GetLastError();
        VirtualFreeEx(hProcess, allocMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        std::cerr << "Failed to get handle for kernel32 " << GetLastError();
        VirtualFreeEx(hProcess, allocMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"), allocMemory, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread in target process! Error: " << GetLastError();
        VirtualFreeEx(hProcess, allocMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, allocMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "DLL injected successfully!" << std::endl;
    return true;
}

int main() {
    std::vector<std::string> processList;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot!" << std::endl;
        return 1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            processList.push_back(pe32.szExeFile);
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    if (processList.empty()) {
        std::cerr << "No processes found!" << std::endl;
        return 1;
    }

    std::cout << "Select a process to inject into:" << std::endl;
    for (size_t i = 0; i < processList.size(); ++i) {
        std::cout << i + 1 << ". " << processList[i] << std::endl;
    }

    size_t choice = 0;
    std::cout << "Enter the number of the process: ";
    std::cin >> choice;
    std::cin.clear();
    std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

    if (choice < 1 || choice > processList.size()) {
        std::cerr << "Invalid choice!" << std::endl;
        return 1;
    }

    std::string processName = processList[choice - 1];
    std::string dllPath;
    std::cout << "Enter the full path of the DLL to inject: ";
    std::getline(std::cin, dllPath);

    InjectDLL(processName, dllPath);

    return 0;
}
