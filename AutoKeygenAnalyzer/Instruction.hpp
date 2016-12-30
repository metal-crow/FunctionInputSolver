#ifndef INSTRUCTIONS_H
#define INSTRUCTIONS_H

#include <stdint.h>
#include <vector>
#include <assert.h>

#include <capstone.h>

//Defines what each instruction is doing. 
typedef enum {
	LOAD,
	MOVE,//only for moving in an immediate
	STORE,
	ADD,
	SUBTRACT,
	MULTIPLY,
	DIVIDE,
	AND,
	OR,
	XOR,
	BIT_INVERT,
	ABS_VAL,
	CMP_JMP,//only inspect compare if its immediatly followed by jmp (or its built in)
} Instruction_Types;

class Instruction {
public:
	uint32_t register_i_to;
	std::vector<uint32_t> register_i_from;//max size of 2, min of 1

	uint64_t mem_address_to;
	uint64_t mem_address_from;
	uint8_t num_read_bytes;

	Instruction_Types action;
};

bool init_capstone(cs_arch asm_arch, cs_mode asm_mode);

//necessary to convert 1 instruction to multiple instructions for simplification purposes
std::vector<Instruction> convert_asm_to_instruction(uint8_t* asm_bytes, uint32_t size);

#endif