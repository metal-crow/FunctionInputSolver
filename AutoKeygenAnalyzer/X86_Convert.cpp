#include <vector>
#include <assert.h>

#include "X86_Convert.hpp"
#include "ProgramState.hpp"

typedef struct {
	x86_reg parent;
	uint8_t size_in_bytes;
	uint8_t byte_offset_left;//only 1 for AH,BH, etc. 0 for others
} X86_Register_Info;

//need to merge all subregisters (rax, eax, ax, ah, al) into their parent register 
//returns
//	the register that the subregisters map to
//	the actual size of the given register
//	also handle the special case AH regisers, since the result is placed in the 2nd least sig byte, by returning offset
static X86_Register_Info X86_Register_Converter(x86_reg reg){
	switch (reg){
		case X86_REG_AH:
			return{ X86_REG_RAX, 1, 1 };
		case X86_REG_AL:
			return{ X86_REG_RAX, 1, 0 };
		case X86_REG_AX:
			return{ X86_REG_RAX, 2, 0 };
		case X86_REG_BH:
			return{ X86_REG_RBX, 1, 1 };
		case X86_REG_BL:
			return{ X86_REG_RBX, 1, 0 };
		case X86_REG_BP:
			return{ X86_REG_RBP, 2, 0 };
		case X86_REG_BPL:
			return{ X86_REG_RBP, 1, 0 };
		case X86_REG_BX:
			return{ X86_REG_RBX, 2, 0 };
		case X86_REG_CH:
			return{ X86_REG_RCX, 1, 1 };
		case X86_REG_CL:
			return{ X86_REG_RCX, 1, 0 };
		case X86_REG_CS:
			return{ X86_REG_CS, 0, 0 };
		case X86_REG_CX:
			return{ X86_REG_RCX, 2, 0 };
		case X86_REG_DH:
			return{ X86_REG_RDX, 1, 1 };
		case X86_REG_DI:
			return{ X86_REG_RDI, 2, 0 };
		case X86_REG_DIL:
			return{ X86_REG_RDI, 1, 0 };
		case X86_REG_DL:
			return{ X86_REG_RDX, 1, 0 };
		case X86_REG_DS:
			return{ X86_REG_DS, 0, 0 };
		case X86_REG_DX:
			return{ X86_REG_RDX, 2, 0 };
		case X86_REG_EAX:
			return{ X86_REG_RAX, 4, 0 };
		case X86_REG_EBP:
			return{ X86_REG_RBP, 4, 0 };
		case X86_REG_EBX:
			return{ X86_REG_RBX, 4, 0 };
		case X86_REG_ECX:
			return{ X86_REG_RCX, 4, 0 };
		case X86_REG_EDI:
			return{ X86_REG_RDI, 4, 0 };
		case X86_REG_EDX:
			return{ X86_REG_RDX, 4, 0 };
		case X86_REG_EFLAGS:
			return{ X86_REG_EFLAGS, 0, 0 };
		case X86_REG_EIP:
			return{ X86_REG_EIP, 0, 0 };
		case X86_REG_EIZ:
			return{ X86_REG_EIZ, 0, 0 };
		case X86_REG_ES:
			return{ X86_REG_ES, 0, 0 };
		case X86_REG_ESI:
			return{ X86_REG_RSI, 4, 0 };
		case X86_REG_ESP:
			return{ X86_REG_RSP, 4, 0 };
		case X86_REG_FPSW:
			return{ X86_REG_FPSW, 0, 0 };
		case X86_REG_FS:
			return{ X86_REG_FS, 0, 0 };
		case X86_REG_GS:
			return{ X86_REG_GS, 0, 0 };
		case X86_REG_IP:
			return{ X86_REG_IP, 0, 0 };
		case X86_REG_RAX:
			return{ X86_REG_RAX, 8, 0 };
		case X86_REG_RBP:
			return{ X86_REG_RBP, 8, 0 };
		case X86_REG_RBX:
			return{ X86_REG_RBX, 8, 0 };
		case X86_REG_RCX:
			return{ X86_REG_RCX, 8, 0 };
		case X86_REG_RDI:
			return{ X86_REG_RDI, 8, 0 };
		case X86_REG_RDX:
			return{ X86_REG_RDX, 8, 0 };
		case X86_REG_RIP:
			return{ X86_REG_RIP, 0, 0 };
		case X86_REG_RIZ:
			return{ X86_REG_RIZ, 0, 0 };
		case X86_REG_RSI:
			return{ X86_REG_RSI, 8, 0 };
		case X86_REG_RSP:
			return{ X86_REG_RSP, 8, 0 };
		case X86_REG_SI:
			return{ X86_REG_RSI, 2, 0 };
		case X86_REG_SIL:
			return{ X86_REG_RSI, 1, 0 };
		case X86_REG_SP:
			return{ X86_REG_RSP, 2, 0 };
		case X86_REG_SPL:
			return{ X86_REG_RSP, 1, 0 };
		case X86_REG_SS:
			return{ X86_REG_SS, 0, 0 };
		case X86_REG_CR0:
			return{ X86_REG_CR0, 0, 0 };
		case X86_REG_CR1:
			return{ X86_REG_CR1, 0, 0 };
		case X86_REG_CR2:
			return{ X86_REG_CR2, 0, 0 };
		case X86_REG_CR3:
			return{ X86_REG_CR3, 0, 0 };
		case X86_REG_CR4:
			return{ X86_REG_CR4, 0, 0 };
		case X86_REG_CR5:
			return{ X86_REG_CR5, 0, 0 };
		case X86_REG_CR6:
			return{ X86_REG_CR6, 0, 0 };
		case X86_REG_CR7:
			return{ X86_REG_CR7, 0, 0 };
		case X86_REG_CR8:
			return{ X86_REG_CR8, 0, 0 };
		case X86_REG_CR9:
			return{ X86_REG_CR9, 0, 0 };
		case X86_REG_CR10:
			return{ X86_REG_CR10, 0, 0 };
		case X86_REG_CR11:
			return{ X86_REG_CR11, 0, 0 };
		case X86_REG_CR12:
			return{ X86_REG_CR12, 0, 0 };
		case X86_REG_CR13:
			return{ X86_REG_CR13, 0, 0 };
		case X86_REG_CR14:
			return{ X86_REG_CR14, 0, 0 };
		case X86_REG_CR15:
			return{ X86_REG_CR15, 0, 0 };
		case X86_REG_DR0:
			return{ X86_REG_DR0, 0, 0 };
		case X86_REG_DR1:
			return{ X86_REG_DR1, 0, 0 };
		case X86_REG_DR2:
			return{ X86_REG_DR2, 0, 0 };
		case X86_REG_DR3:
			return{ X86_REG_DR3, 0, 0 };
		case X86_REG_DR4:
			return{ X86_REG_DR4, 0, 0 };
		case X86_REG_DR5:
			return{ X86_REG_DR5, 0, 0 };
		case X86_REG_DR6:
			return{ X86_REG_DR6, 0, 0 };
		case X86_REG_DR7:
			return{ X86_REG_DR7, 0, 0 };
		case X86_REG_FP0:
			return{ X86_REG_FP0, 0, 0 };
		case X86_REG_FP1:
			return{ X86_REG_FP1, 0, 0 };
		case X86_REG_FP2:
			return{ X86_REG_FP2, 0, 0 };
		case X86_REG_FP3:
			return{ X86_REG_FP3, 0, 0 };
		case X86_REG_FP4:
			return{ X86_REG_FP4, 0, 0 };
		case X86_REG_FP5:
			return{ X86_REG_FP5, 0, 0 };
		case X86_REG_FP6:
			return{ X86_REG_FP6, 0, 0 };
		case X86_REG_FP7:
			return{ X86_REG_FP7, 0, 0 };
		case X86_REG_K0:
			return{ X86_REG_K0, 0, 0 };
		case X86_REG_K1:
			return{ X86_REG_K1, 0, 0 };
		case X86_REG_K2:
			return{ X86_REG_K2, 0, 0 };
		case X86_REG_K3:
			return{ X86_REG_K3, 0, 0 };
		case X86_REG_K4:
			return{ X86_REG_K4, 0, 0 };
		case X86_REG_K5:
			return{ X86_REG_K5, 0, 0 };
		case X86_REG_K6:
			return{ X86_REG_K6, 0, 0 };
		case X86_REG_K7:
			return{ X86_REG_K7, 0, 0 };
		case X86_REG_MM0:
			return{ X86_REG_MM0, 0, 0 };
		case X86_REG_MM1:
			return{ X86_REG_MM1, 0, 0 };
		case X86_REG_MM2:
			return{ X86_REG_MM2, 0, 0 };
		case X86_REG_MM3:
			return{ X86_REG_MM3, 0, 0 };
		case X86_REG_MM4:
			return{ X86_REG_MM4, 0, 0 };
		case X86_REG_MM5:
			return{ X86_REG_MM5, 0, 0 };
		case X86_REG_MM6:
			return{ X86_REG_MM6, 0, 0 };
		case X86_REG_MM7:
			return{ X86_REG_MM7, 0, 0 };
		case X86_REG_R8:
			return{ X86_REG_R8, 8, 0 };
		case X86_REG_R9:
			return{ X86_REG_R9, 8, 0 };
		case X86_REG_R10:
			return{ X86_REG_R10, 8, 0 };
		case X86_REG_R11:
			return{ X86_REG_R11, 8, 0 };
		case X86_REG_R12:
			return{ X86_REG_R12, 8, 0 };
		case X86_REG_R13:
			return{ X86_REG_R13, 8, 0 };
		case X86_REG_R14:
			return{ X86_REG_R14, 8, 0 };
		case X86_REG_R15:
			return{ X86_REG_R15, 8, 0 };
		case X86_REG_ST0:
			return{ X86_REG_ST0, 0, 0 };
		case X86_REG_ST1:
			return{ X86_REG_ST1, 0, 0 };
		case X86_REG_ST2:
			return{ X86_REG_ST2, 0, 0 };
		case X86_REG_ST3:
			return{ X86_REG_ST3, 0, 0 };
		case X86_REG_ST4:
			return{ X86_REG_ST4, 0, 0 };
		case X86_REG_ST5:
			return{ X86_REG_ST5, 0, 0 };
		case X86_REG_ST6:
			return{ X86_REG_ST6, 0, 0 };
		case X86_REG_ST7:
			return{ X86_REG_ST7, 0, 0 };
		case X86_REG_XMM0:
			return{ X86_REG_XMM0, 0, 0 };
		case X86_REG_XMM1:
			return{ X86_REG_XMM1, 0, 0 };
		case X86_REG_XMM2:
			return{ X86_REG_XMM2, 0, 0 };
		case X86_REG_XMM3:
			return{ X86_REG_XMM3, 0, 0 };
		case X86_REG_XMM4:
			return{ X86_REG_XMM4, 0, 0 };
		case X86_REG_XMM5:
			return{ X86_REG_XMM5, 0, 0 };
		case X86_REG_XMM6:
			return{ X86_REG_XMM6, 0, 0 };
		case X86_REG_XMM7:
			return{ X86_REG_XMM7, 0, 0 };
		case X86_REG_XMM8:
			return{ X86_REG_XMM8, 0, 0 };
		case X86_REG_XMM9:
			return{ X86_REG_XMM9, 0, 0 };
		case X86_REG_XMM10:
			return{ X86_REG_XMM10, 0, 0 };
		case X86_REG_XMM11:
			return{ X86_REG_XMM11, 0, 0 };
		case X86_REG_XMM12:
			return{ X86_REG_XMM12, 0, 0 };
		case X86_REG_XMM13:
			return{ X86_REG_XMM13, 0, 0 };
		case X86_REG_XMM14:
			return{ X86_REG_XMM14, 0, 0 };
		case X86_REG_XMM15:
			return{ X86_REG_XMM15, 0, 0 };
		case X86_REG_XMM16:
			return{ X86_REG_XMM16, 0, 0 };
		case X86_REG_XMM17:
			return{ X86_REG_XMM17, 0, 0 };
		case X86_REG_XMM18:
			return{ X86_REG_XMM18, 0, 0 };
		case X86_REG_XMM19:
			return{ X86_REG_XMM19, 0, 0 };
		case X86_REG_XMM20:
			return{ X86_REG_XMM20, 0, 0 };
		case X86_REG_XMM21:
			return{ X86_REG_XMM21, 0, 0 };
		case X86_REG_XMM22:
			return{ X86_REG_XMM22, 0, 0 };
		case X86_REG_XMM23:
			return{ X86_REG_XMM23, 0, 0 };
		case X86_REG_XMM24:
			return{ X86_REG_XMM24, 0, 0 };
		case X86_REG_XMM25:
			return{ X86_REG_XMM25, 0, 0 };
		case X86_REG_XMM26:
			return{ X86_REG_XMM26, 0, 0 };
		case X86_REG_XMM27:
			return{ X86_REG_XMM27, 0, 0 };
		case X86_REG_XMM28:
			return{ X86_REG_XMM28, 0, 0 };
		case X86_REG_XMM29:
			return{ X86_REG_XMM29, 0, 0 };
		case X86_REG_XMM30:
			return{ X86_REG_XMM30, 0, 0 };
		case X86_REG_XMM31:
			return{ X86_REG_XMM31, 0, 0 };
		case X86_REG_YMM0:
			return{ X86_REG_YMM0, 0, 0 };
		case X86_REG_YMM1:
			return{ X86_REG_YMM1, 0, 0 };
		case X86_REG_YMM2:
			return{ X86_REG_YMM2, 0, 0 };
		case X86_REG_YMM3:
			return{ X86_REG_YMM3, 0, 0 };
		case X86_REG_YMM4:
			return{ X86_REG_YMM4, 0, 0 };
		case X86_REG_YMM5:
			return{ X86_REG_YMM5, 0, 0 };
		case X86_REG_YMM6:
			return{ X86_REG_YMM6, 0, 0 };
		case X86_REG_YMM7:
			return{ X86_REG_YMM7, 0, 0 };
		case X86_REG_YMM8:
			return{ X86_REG_YMM8, 0, 0 };
		case X86_REG_YMM9:
			return{ X86_REG_YMM9, 0, 0 };
		case X86_REG_YMM10:
			return{ X86_REG_YMM10, 0, 0 };
		case X86_REG_YMM11:
			return{ X86_REG_YMM11, 0, 0 };
		case X86_REG_YMM12:
			return{ X86_REG_YMM12, 0, 0 };
		case X86_REG_YMM13:
			return{ X86_REG_YMM13, 0, 0 };
		case X86_REG_YMM14:
			return{ X86_REG_YMM14, 0, 0 };
		case X86_REG_YMM15:
			return{ X86_REG_YMM15, 0, 0 };
		case X86_REG_YMM16:
			return{ X86_REG_YMM16, 0, 0 };
		case X86_REG_YMM17:
			return{ X86_REG_YMM17, 0, 0 };
		case X86_REG_YMM18:
			return{ X86_REG_YMM18, 0, 0 };
		case X86_REG_YMM19:
			return{ X86_REG_YMM19, 0, 0 };
		case X86_REG_YMM20:
			return{ X86_REG_YMM20, 0, 0 };
		case X86_REG_YMM21:
			return{ X86_REG_YMM21, 0, 0 };
		case X86_REG_YMM22:
			return{ X86_REG_YMM22, 0, 0 };
		case X86_REG_YMM23:
			return{ X86_REG_YMM23, 0, 0 };
		case X86_REG_YMM24:
			return{ X86_REG_YMM24, 0, 0 };
		case X86_REG_YMM25:
			return{ X86_REG_YMM25, 0, 0 };
		case X86_REG_YMM26:
			return{ X86_REG_YMM26, 0, 0 };
		case X86_REG_YMM27:
			return{ X86_REG_YMM27, 0, 0 };
		case X86_REG_YMM28:
			return{ X86_REG_YMM28, 0, 0 };
		case X86_REG_YMM29:
			return{ X86_REG_YMM29, 0, 0 };
		case X86_REG_YMM30:
			return{ X86_REG_YMM30, 0, 0 };
		case X86_REG_YMM31:
			return{ X86_REG_YMM31, 0, 0 };
		case X86_REG_ZMM0:
			return{ X86_REG_ZMM0, 0, 0 };
		case X86_REG_ZMM1:
			return{ X86_REG_ZMM1, 0, 0 };
		case X86_REG_ZMM2:
			return{ X86_REG_ZMM2, 0, 0 };
		case X86_REG_ZMM3:
			return{ X86_REG_ZMM3, 0, 0 };
		case X86_REG_ZMM4:
			return{ X86_REG_ZMM4, 0, 0 };
		case X86_REG_ZMM5:
			return{ X86_REG_ZMM5, 0, 0 };
		case X86_REG_ZMM6:
			return{ X86_REG_ZMM6, 0, 0 };
		case X86_REG_ZMM7:
			return{ X86_REG_ZMM7, 0, 0 };
		case X86_REG_ZMM8:
			return{ X86_REG_ZMM8, 0, 0 };
		case X86_REG_ZMM9:
			return{ X86_REG_ZMM9, 0, 0 };
		case X86_REG_ZMM10:
			return{ X86_REG_ZMM10, 0, 0 };
		case X86_REG_ZMM11:
			return{ X86_REG_ZMM11, 0, 0 };
		case X86_REG_ZMM12:
			return{ X86_REG_ZMM12, 0, 0 };
		case X86_REG_ZMM13:
			return{ X86_REG_ZMM13, 0, 0 };
		case X86_REG_ZMM14:
			return{ X86_REG_ZMM14, 0, 0 };
		case X86_REG_ZMM15:
			return{ X86_REG_ZMM15, 0, 0 };
		case X86_REG_ZMM16:
			return{ X86_REG_ZMM16, 0, 0 };
		case X86_REG_ZMM17:
			return{ X86_REG_ZMM17, 0, 0 };
		case X86_REG_ZMM18:
			return{ X86_REG_ZMM18, 0, 0 };
		case X86_REG_ZMM19:
			return{ X86_REG_ZMM19, 0, 0 };
		case X86_REG_ZMM20:
			return{ X86_REG_ZMM20, 0, 0 };
		case X86_REG_ZMM21:
			return{ X86_REG_ZMM21, 0, 0 };
		case X86_REG_ZMM22:
			return{ X86_REG_ZMM22, 0, 0 };
		case X86_REG_ZMM23:
			return{ X86_REG_ZMM23, 0, 0 };
		case X86_REG_ZMM24:
			return{ X86_REG_ZMM24, 0, 0 };
		case X86_REG_ZMM25:
			return{ X86_REG_ZMM25, 0, 0 };
		case X86_REG_ZMM26:
			return{ X86_REG_ZMM26, 0, 0 };
		case X86_REG_ZMM27:
			return{ X86_REG_ZMM27, 0, 0 };
		case X86_REG_ZMM28:
			return{ X86_REG_ZMM28, 0, 0 };
		case X86_REG_ZMM29:
			return{ X86_REG_ZMM29, 0, 0 };
		case X86_REG_ZMM30:
			return{ X86_REG_ZMM30, 0, 0 };
		case X86_REG_ZMM31:
			return{ X86_REG_ZMM31, 0, 0 };
		case X86_REG_R8B:
			return{ X86_REG_R8, 1, 0 };
		case X86_REG_R9B:
			return{ X86_REG_R9, 1, 0 };
		case X86_REG_R10B:
			return{ X86_REG_R10, 1, 0 };
		case X86_REG_R11B:
			return{ X86_REG_R11, 1, 0 };
		case X86_REG_R12B:
			return{ X86_REG_R12, 1, 0 };
		case X86_REG_R13B:
			return{ X86_REG_R13, 1, 0 };
		case X86_REG_R14B:
			return{ X86_REG_R14, 1, 0 };
		case X86_REG_R15B:
			return{ X86_REG_R15, 1, 0 };
		case X86_REG_R8D:
			return{ X86_REG_R8, 4, 0 };
		case X86_REG_R9D:
			return{ X86_REG_R9, 4, 0 };
		case X86_REG_R10D:
			return{ X86_REG_R10, 4, 0 };
		case X86_REG_R11D:
			return{ X86_REG_R11, 4, 0 };
		case X86_REG_R12D:
			return{ X86_REG_R12, 4, 0 };
		case X86_REG_R13D:
			return{ X86_REG_R13, 4, 0 };
		case X86_REG_R14D:
			return{ X86_REG_R14, 4, 0 };
		case X86_REG_R15D:
			return{ X86_REG_R15, 4, 0 };
		case X86_REG_R8W:
			return{ X86_REG_R8, 2, 0 };
		case X86_REG_R9W:
			return{ X86_REG_R9, 2, 0 };
		case X86_REG_R10W:
			return{ X86_REG_R10, 2, 0 };
		case X86_REG_R11W:
			return{ X86_REG_R11, 2, 0 };
		case X86_REG_R12W:
			return{ X86_REG_R12, 2, 0 };
		case X86_REG_R13W:
			return{ X86_REG_R13, 2, 0 };
		case X86_REG_R14W:
			return{ X86_REG_R14, 2, 0 };
		case X86_REG_R15W:
			return{ X86_REG_R15, 2, 0 };
	}
}

void interpret_x86(std::vector<Instruction>* instructions, cs_insn *decod_instr){
	Instruction instr;

	/* Determine instruction operands and their type */
	for (uint8_t i = 0; i < decod_instr->detail->x86.op_count; i++){
		cs_x86_op operand = decod_instr->detail->x86.operands[i];
		//FIXME assuming 1st register is always destination right now
		switch (operand.type){
			case X86_OP_REG:
			{
				//since there is no memory to memory instruction, and x86 assembles a n-byte ptr load to the corrisponding register size, this works
				X86_Register_Info reg_info = X86_Register_Converter(operand.reg);
				assert(reg_info.size_in_bytes > 0);
				instr.num_read_bytes = reg_info.size_in_bytes;//Size of given register. Can have this in loop since all register sizes must match
				//handle AH, BH, etc case.
				if (reg_info.byte_offset_left > 0){
					assert(false);//TODO guhhhhhh how do handle writes into subbytes of a register?
				}

				if (i == 0){
					instr.register_i_to = reg_info.parent;
				}
				else{
					instr.register_i_from.push_back(reg_info.parent);
				}
				break;
			}

			case X86_OP_IMM:
			{
				assert(i != 0);//destination can't be immediate
				instr.constant_val_has = true;
				instr.constant_val = operand.imm;
				break;
			}

			case X86_OP_MEM:
			{
				//create an action chain defining the memory location using the used regiser's action chain and the immediates
				//base + index*scale + disp 
				std::vector<Action> actions;
				if (operand.mem.segment != X86_REG_INVALID){
					Action act;
					Init_Action(&act, ADD, current_program_state.registers[operand.mem.segment].action_chain);
					actions.push_back(act);
				}
				if (operand.mem.base != X86_REG_INVALID){
					Action act;
					Init_Action(&act, ADD, current_program_state.registers[operand.mem.base].action_chain);
					actions.push_back(act);
				}
				if (operand.mem.index != X86_REG_INVALID){
					std::vector<Action> act;

					Action a1;
					Init_Action(&a1, ADD, current_program_state.registers[operand.mem.index].action_chain);
					act.push_back(a1);

					Action a2;
					Init_Action(&a2, MULTIPLY, CONSTANT, operand.mem.scale);
					act.push_back(a2);

					Action act_index_n_scale;
					Init_Action(&act_index_n_scale, ADD, act);
					actions.push_back(act_index_n_scale);
				}
				Action act_disp;
				Init_Action(&act_disp, ADD, CONSTANT, operand.mem.disp);
				actions.push_back(act_disp);

				Action act_final;
				Init_Action(&act_final, ADD, actions);
				if (i == 0){
					instr.mem_address_to = act_final;
				}
				else{
					instr.mem_address_from = act_final;
				}
				break;
			}

			//not going to handle floating point right now
			case X86_OP_FP:
			default:
				assert(false);
				break;
		}
	}
	assert(instr.num_read_bytes > 0);

	/* Determine instruction type */
	switch (decod_instr->id){
		//ADD
		case X86_INS_ADC:
		case X86_INS_ADCX:
		case X86_INS_ADD:
		case X86_INS_ADOX:
		{
			instr.action = ADD;
			instructions->push_back(instr);
			break;
		}
		//AND
		case X86_INS_AND:
		{
			instr.action = AND;
			instructions->push_back(instr);
			break;
		}
		case X86_INS_ANDN:
		{
			Instruction instr2;
			memcpy(&instr2, &instr, sizeof(Instruction));
			instr.action = AND;
			instructions->push_back(instr);
			instr2.action = BIT_INVERT;
			instructions->push_back(instr2);
			break;
		}
		// LOAD/MOVE/STORE
		case X86_INS_MOV:
			if (decod_instr->detail->x86.operands[0].type == X86_OP_REG && decod_instr->detail->x86.operands[1].type == X86_OP_MEM){
				instr.action = LOAD;
				instructions->push_back(instr);
			}
			else if (decod_instr->detail->x86.operands[0].type == X86_OP_REG && decod_instr->detail->x86.operands[1].type == X86_OP_IMM){
				instr.action = MOVE;
				instructions->push_back(instr);
			}
			else if (decod_instr->detail->x86.operands[0].type == X86_OP_REG && decod_instr->detail->x86.operands[1].type == X86_OP_REG){

			}
			else if (decod_instr->detail->x86.operands[0].type == X86_OP_MEM && decod_instr->detail->x86.operands[1].type == X86_OP_REG){
				instr.action = STORE;
				instructions->push_back(instr);
			}
			else if (decod_instr->detail->x86.operands[0].type == X86_OP_MEM && decod_instr->detail->x86.operands[1].type == X86_OP_MEM){

			}
			else if (decod_instr->detail->x86.operands[0].type == X86_OP_MEM && decod_instr->detail->x86.operands[1].type == X86_OP_IMM){
				instr.action = MOVE;
				instructions->push_back(instr);
			}
			break;
			//SUBTRACT,
			//MULTIPLY,
			//DIVIDE,
			//OR,
			//XOR,
			//BIT_INVERT,
			//ABS_VAL,
			//CMP_JMP
	}
}