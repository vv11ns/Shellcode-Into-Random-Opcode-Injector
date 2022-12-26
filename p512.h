#include <Windows.h>
#include <winternl.h>
HMODULE hNtDll = GetModuleHandleA("ntdll.dll");

using NtCreateFileProt = DWORD(WINAPI*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
using NtWriteFileProt = DWORD(WINAPI*)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
using NtQueryInformationFileProt = DWORD(WINAPI*)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, int FileInformationClass);
using NtOpenFileProt = DWORD(WINAPI*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
using NtAllocateVirtualMemoryProt = DWORD(WINAPI*)(HANDLE, OUT PVOID, ULONG, OUT PULONG, ULONG, ULONG);
using NtReadFileProt = DWORD(WINAPI*)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

void* NtQueryInformationFileAdr = (void*)GetProcAddress(hNtDll, "NtQueryInformationFile");
void* NtCreateFileAdr = (void*)GetProcAddress(hNtDll, "NtCreateFile");
void* NtWriteFileAdr = (void*)GetProcAddress(hNtDll, "NtWriteFile");
void* NtOpenFileAdr = (void*)GetProcAddress(hNtDll, "NtOpenFile");
void* NtAllocateVirtualMemoryAdr = (void*)GetProcAddress(hNtDll, "NtAllocateVirtualMemory");
void* NtReadFileAdr = (void*)GetProcAddress(hNtDll, "NtReadFile");
void* NtProtectVirtualMemoryAdr = (void*)GetProcAddress(hNtDll, "NtProtectVirtualMemory");

NtQueryInformationFileProt NtQueryInformationFileP = (NtQueryInformationFileProt)NtQueryInformationFileAdr;
NtOpenFileProt NtOpenFileP = (NtOpenFileProt)NtOpenFileAdr;
NtCreateFileProt NtCreateFileP = (NtCreateFileProt)NtCreateFileAdr;
NtWriteFileProt NtWriteFileP = (NtWriteFileProt)NtWriteFileAdr;
NtAllocateVirtualMemoryProt NtAllocateVirtualMemoryP = (NtAllocateVirtualMemoryProt)NtAllocateVirtualMemoryAdr;
NtReadFileProt NtReadFileP = (NtReadFileProt)NtReadFileAdr;

namespace p512 {
    void mmemcpy(void* dest, void* source, size_t size) {
        for (int i = 0; i < size; i++) {
            ((char*)dest)[i] = ((char*)source)[i];
        }
    }
    size_t mstrlen(char* str) {
        for (int i = 0; i < INT_MAX; i++) {
            if (str[i] == char(0)) {
                return i;
            }
        }
        return 0;
    }
    void charToWchar(wchar_t* buffer, char* c, size_t sizeOfC) {
        for (int i = 0; i < sizeOfC; i++) {
            buffer[i] = c[i];
        }
    }

    bool charPathToNthCharPath(char* buffer, size_t strlenbuffer) {
        char nth[] = "\\??\\";
        bool nthcont = 1;
        for (int i = 0; i < sizeof(nth) - 1; i++) {
            if (buffer[i] != nth[i]) {
                nthcont = 0;
                break;
            }
        }
        if (!nthcont) {
            char copyOfBuffer[MAX_PATH];
            mmemcpy(&copyOfBuffer, buffer, strlenbuffer);
            mmemcpy(buffer + sizeof(nth) - 1, &copyOfBuffer, strlenbuffer);
            for (int i = 0; i < sizeof(nth) - 1; i++) {
                buffer[i] = nth[i];
            }
        }
        return !nthcont;
    }

    void PCHARpathtoPWCHAR_TNTHpath(wchar_t* buffer, char* path, size_t& outputSize) {
        outputSize = mstrlen(path);
        char NTHPath[MAX_PATH];
        mmemcpy(NTHPath, path, outputSize);
        if (charPathToNthCharPath(NTHPath, outputSize)) {
            outputSize += 4;
        }
        charToWchar(buffer, NTHPath, outputSize);
    }

    DWORD RVAtoFileOffset(PIMAGE_NT_HEADERS NTHeaders, DWORD dwRVA) {
        int wSections = NTHeaders->FileHeader.NumberOfSections;
        PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NTHeaders);
        for (int i = 0; i < wSections; i++) {
            if ((SectionHeader->VirtualAddress <= dwRVA) && ((SectionHeader->VirtualAddress + SectionHeader->Misc.VirtualSize) >= dwRVA)) {
                dwRVA = dwRVA - SectionHeader->VirtualAddress + SectionHeader->PointerToRawData;
                return dwRVA;
            }
            SectionHeader++;
        }
        return -1;
    }
    void changeBytesInArray(byte* array, byte* from, byte* to, int sizeofArray, int sizeofChangeArr) {
        int step = sizeofChangeArr;
        for (int i = 0; i < sizeofArray; i++) {
            bool same = true;
            for (int j = i; j < i + step; j++) {
                if (array[j] != from[j - i]) {
                    same = false;
                    break;
                }
            }
            if (same) {
                for (int j = i; j < i + step; j++) {
                    array[j] = to[j - i];
                }
                i += step - 1;
            }
        }
    }
    void* mmalloc(size_t size) {
        ULONG sizeToAllocate = size;
        void* adr = 0;
        NtAllocateVirtualMemoryP(HANDLE(-1), &adr, 0, &sizeToAllocate, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        return adr;
    }
}

namespace p512file {
    typedef struct _FILE_STANDARD_INFORMATION { LARGE_INTEGER AllocationSize; LARGE_INTEGER EndOfFile; ULONG  NumberOfLinks; BOOLEAN DeletePending; BOOLEAN Directory; } FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;
    void WriteBytes(char* path, char* bytes, size_t sizeOfBytes) {
        size_t sizeOfPath = p512::mstrlen(path);
        char newPath[MAX_PATH];
        p512::mmemcpy(&newPath, path, sizeOfPath);
        bool isnthAdded = p512::charPathToNthCharPath(newPath, sizeOfPath);
        if (isnthAdded)
            sizeOfPath += 4;
        wchar_t wcPath[MAX_PATH];
        p512::charToWchar(wcPath, newPath, sizeOfPath);

        HANDLE FileHandle;

        OBJECT_ATTRIBUTES objectAttributes = {};
        UNICODE_STRING us;
        us.Buffer = wcPath;
        us.Length = sizeOfPath * 2;
        us.MaximumLength = us.Length;
        objectAttributes.Length = sizeof(objectAttributes);
        objectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
        objectAttributes.ObjectName = &us;

        IO_STATUS_BLOCK isb = {};
        IO_STATUS_BLOCK isb2 = {};
        NtCreateFileP(&FileHandle, GENERIC_ALL, &objectAttributes, &isb, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, 0, NULL, 0);
        LARGE_INTEGER offset;
        offset.QuadPart = 0;
        NtWriteFileP(FileHandle, 0, 0, 0, &isb2, bytes, sizeOfBytes, &offset, 0);
        CloseHandle(FileHandle);
    }
    ULONG getFileSize(HANDLE FileHandle) {
        IO_STATUS_BLOCK IO = {};
        FILE_STANDARD_INFORMATION FSI = {};
        NtQueryInformationFileP(FileHandle, &IO, &FSI, sizeof(FSI), 5);
        return FSI.EndOfFile.LowPart;
    }
    void* ReadAllBytes(char* path, ULONG& sizeOfFile) {
        size_t sizeOfWCPath = 0;
        wchar_t wcPath[MAX_PATH];
        p512::PCHARpathtoPWCHAR_TNTHpath(wcPath, path, sizeOfWCPath);

        HANDLE FileHandle;
        OBJECT_ATTRIBUTES objectAttributes = {};
        UNICODE_STRING us;
        us.Buffer = wcPath;
        us.Length = sizeOfWCPath * 2;
        us.MaximumLength = us.Length;
        objectAttributes.Length = sizeof(objectAttributes);
        objectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
        objectAttributes.ObjectName = &us;
        IO_STATUS_BLOCK IO = {};
        NtOpenFileP(&FileHandle, GENERIC_READ, &objectAttributes, &IO, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
        sizeOfFile = getFileSize(FileHandle);
        void* buffer = p512::mmalloc(sizeOfFile);

        IO_STATUS_BLOCK IO2 = {};
        LARGE_INTEGER LI;
        LI.QuadPart = 0;

        NtReadFileP(FileHandle, 0, 0, 0, &IO2, buffer, sizeOfFile, &LI, 0);
        CloseHandle(FileHandle);
        return buffer;
    }
}
