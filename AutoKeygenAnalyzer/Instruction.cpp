#include <assert.h>

#include "Instruction.hpp"
#include "X86_Convert.hpp"

static csh handle = NULL;
static cs_arch asm_arch;

bool init_capstone(cs_arch asm_arch_arg, cs_mode asm_mode){
	asm_arch = asm_arch_arg;
	cs_err err = cs_open(asm_arch, asm_mode, &handle);
	cs_err err2 = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	return (err == CS_ERR_OK && err2 == CS_ERR_OK);
}

std::vector<Instruction> convert_asm_to_instruction(uint8_t* asm_bytes, uint32_t size){
	assert(handle != NULL);
	std::vector<Instruction> instructions;

	cs_insn *decod_instr;
	//TODO what is the address arg for?
	size_t count = cs_disasm(handle, asm_bytes, size, 0x1000, 1, &decod_instr);
	assert(count == 1);

	//map from an actual instruction to our generic Instruction struct
	switch (asm_arch){
		case CS_ARCH_ARM:
			break;
		case CS_ARCH_ARM64:
			break;
		case CS_ARCH_MIPS:
			break;
		case CS_ARCH_X86:
			interpret_x86(&instructions, decod_instr);
			break;
		case CS_ARCH_PPC:
			break;
		case CS_ARCH_SPARC:
			break;
		case CS_ARCH_SYSZ:
			break;
		case CS_ARCH_XCORE:
			break;
		case CS_ARCH_MAX:
			break;
	}

	cs_free(decod_instr, count);
	return instructions;
}