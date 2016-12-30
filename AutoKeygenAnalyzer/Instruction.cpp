#include "Instruction.hpp"

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

	Instruction instr = Instruction();

	//map from an instruction type to our Instruction_Types
	switch (asm_arch){
		case CS_ARCH_ARM:
			break;
		case CS_ARCH_ARM64:
			break;
		case CS_ARCH_MIPS:
			break;

		case CS_ARCH_X86:
			//determine operands and their type
			for (uint8_t i = 0; i < decod_instr->detail->x86.op_count; i++){
				cs_x86_op operand = decod_instr->detail->x86.operands[i];
				//TODO how to know if source/destination
				switch (operand.type){
					case X86_OP_REG:

					case X86_OP_IMM:
					
					case X86_OP_MEM:

					case X86_OP_FP:
					default:
						assert(false);
						break;
				}
			}
			switch (decod_instr->id){
				//ADD
				case X86_INS_ADC:
				case X86_INS_ADCX:
				case X86_INS_ADD:
				case X86_INS_ADOX:
					instr.action = ADD;
					instructions.push_back(instr);
					break;
				//AND
				case X86_INS_AND:
					instr.action = AND;
					instructions.push_back(instr);
					break;

				case X86_INS_ANDN:
					Instruction instr2;
					memcpy(&instr2, &instr, sizeof(Instruction));
					instr.action = AND;
					instructions.push_back(instr);
					instr2.action = BIT_INVERT;
					instructions.push_back(instr2);
					break;
				//OR,
				//XOR,
				//CMP,
			}
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
	instructions.push_back(instr);

	cs_free(decod_instr, count);
	return instructions;
}