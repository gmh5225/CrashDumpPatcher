#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <DbgHelp.h>
#include <Shlwapi.h>

#define ERROR_INVALID_FORMAT 0x8007000F
#define ERROR_MODULE_NOT_FOUND 0x80070136

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "Dbghelp.lib")

struct FileInfo
{
    DWORD TimeDateStamp;
    DWORD SizeOfImage;
    DWORD CheckSum;
};

class DumpPatcher
{
private:
    const wchar_t *dmp_file_name;
    const wchar_t *exe_file_name;
    FileInfo file_info;

public:
    DumpPatcher(const wchar_t *dmp_file_name, const wchar_t *exe_file_name) :
        dmp_file_name(dmp_file_name), exe_file_name(exe_file_name)
    {
        memset(&file_info, 0, sizeof(file_info));
    }

    int get_file_info()
    {
        HANDLE file = CreateFileW(
            exe_file_name,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0);
        if (file == INVALID_HANDLE_VALUE)
        {
            std::wcerr << L"Can not open \"" << exe_file_name << "\"." << std::endl;
            return 1;
        }

        HANDLE map = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
        if (!map)
        {
            std::wcerr << L"Can not create file mapping for \"" << exe_file_name << "\"." << std::endl;
            CloseHandle(file);
            return 1;
        }

        IMAGE_DOS_HEADER *dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0));
        if (!dos_header)
        {
            std::wcerr << L"Can not map view of file for \"" << exe_file_name << "\"." << std::endl;
            CloseHandle(map);
            CloseHandle(file);
            return 1;
        }

        try
        {
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
                throw ERROR_INVALID_FORMAT;

            IMAGE_NT_HEADERS32 *nt_header32 =
                reinterpret_cast<IMAGE_NT_HEADERS32 *>(reinterpret_cast<byte *>(dos_header) + dos_header->e_lfanew);
            if (nt_header32->Signature != IMAGE_NT_SIGNATURE)
                throw ERROR_INVALID_FORMAT;

            if (nt_header32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                file_info.TimeDateStamp = nt_header32->FileHeader.TimeDateStamp;
                file_info.SizeOfImage = nt_header32->OptionalHeader.SizeOfImage;
                file_info.CheckSum = nt_header32->OptionalHeader.CheckSum;
            }
            else if (nt_header32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                IMAGE_NT_HEADERS64 *nt_header64 = reinterpret_cast<IMAGE_NT_HEADERS64 *>(nt_header32);
                file_info.TimeDateStamp = nt_header64->FileHeader.TimeDateStamp;
                file_info.SizeOfImage = nt_header64->OptionalHeader.SizeOfImage;
                file_info.CheckSum = nt_header64->OptionalHeader.CheckSum;
            }
            else
            {
                throw ERROR_INVALID_FORMAT;
            }
        }
        catch (int error_code)
        {
            std::wcerr << L"File \"" << exe_file_name << "\" has an incorrect format. Error code: " << error_code
                       << std::endl;
            UnmapViewOfFile(dos_header);
            CloseHandle(map);
            CloseHandle(file);
            return error_code;
        }

        UnmapViewOfFile(dos_header);
        CloseHandle(map);
        CloseHandle(file);

        return ERROR_SUCCESS;
    }

    int patch_dump()
    {
        HANDLE file = CreateFileW(
            dmp_file_name,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0);
        if (file == INVALID_HANDLE_VALUE)
        {
            std::wcerr << L"Can not open \"" << dmp_file_name << "\"." << std::endl;
            return 1;
        }

        HANDLE map = CreateFileMapping(file, NULL, PAGE_READWRITE, 0, 0, NULL);
        if (!map)
        {
            std::wcerr << L"Can not create file mapping for \"" << dmp_file_name << "\"." << std::endl;
            CloseHandle(file);
            return 1;
        }

        MINIDUMP_HEADER *header = reinterpret_cast<MINIDUMP_HEADER *>(MapViewOfFile(map, SECTION_MAP_WRITE, 0, 0, 0));
        if (!header)
        {
            std::wcerr << L"Can not map view of file for \"" << dmp_file_name << "\"." << std::endl;
            CloseHandle(map);
            CloseHandle(file);
            return 1;
        }

        int res = ERROR_INVALID_FORMAT;
        try
        {
            if (header->Signature != MINIDUMP_SIGNATURE)
                throw ERROR_INVALID_FORMAT;

            MINIDUMP_DIRECTORY *directory =
                reinterpret_cast<MINIDUMP_DIRECTORY *>(reinterpret_cast<byte *>(header) + header->StreamDirectoryRva);
            for (ULONG32 i = 0; i < header->NumberOfStreams; i++, directory++)
            {
                if (directory->StreamType == ModuleListStream)
                {
                    MINIDUMP_MODULE_LIST *module_list = reinterpret_cast<MINIDUMP_MODULE_LIST *>(
                        reinterpret_cast<byte *>(header) + directory->Location.Rva);
                    for (ULONG32 j = 0; j < module_list->NumberOfModules; j++)
                    {
                        MINIDUMP_MODULE *module = &module_list->Modules[j];
                        if (module->TimeDateStamp == file_info.TimeDateStamp)
                        {
                            module->SizeOfImage = file_info.SizeOfImage;
                            module->CheckSum = file_info.CheckSum;
                            res = ERROR_SUCCESS;
                        }
                    }
                }
            }
            if (res == ERROR_SUCCESS)
            {
                FlushViewOfFile(header, 0);
            }
            else
            {
                throw ERROR_MODULE_NOT_FOUND;
            }
        }
        catch (int error_code)
        {
            std::wcerr << L"Module \"" << PathFindFileNameW(exe_file_name)
                       << "\" not found in the DMP file. Error code: " << error_code << std::endl;
            UnmapViewOfFile(header);
            CloseHandle(map);
            CloseHandle(file);
            return error_code;
        }

        UnmapViewOfFile(header);
        CloseHandle(map);
        CloseHandle(file);

        return ERROR_SUCCESS;
    }
};

int
wmain(int argc, wchar_t *argv[])
{
    if (argc < 3)
    {
        std::wcerr << L"Usage: " << PathFindFileNameW(argv[0]) << L" DmpFile ExeFile" << std::endl;
        return 1;
    }

    const wchar_t *dmp_file_name = argv[1];
    if (wcslen(dmp_file_name) == 0)
    {
        std::wcerr << L"Crash dump file does not found." << std::endl;
        return 1;
    }

    const wchar_t *exe_file_name = argv[2];
    if (wcslen(exe_file_name) == 0)
    {
        std::wcerr << L"Executable file does not found." << std::endl;
        return 1;
    }

    DumpPatcher patcher(dmp_file_name, exe_file_name);
    int error_code = patcher.get_file_info();
    if (error_code != ERROR_SUCCESS)
        return error_code;

    error_code = patcher.patch_dump();
    if (error_code != ERROR_SUCCESS)
        return error_code;

    std::wcout << L"CrashDumpPatcher finished." << std::endl;
    return 0;
}
