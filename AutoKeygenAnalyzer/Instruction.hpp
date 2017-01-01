#ifndef INSTRUCTIONS_H
#define INSTRUCTIONS_H

#include <stdint.h>
#include <vector>

#include <capstone.h>

#include "Action.hpp"
#include "Instruction_Types.hpp"

typedef struct {
	uint32_t register_i_to;
	std::vector<uint32_t> register_i_from;//max size of 2, min of 1

	//since a memory address can use regiser values, define it as an action history
	Action mem_address_to;
	Action mem_address_from;
	uint8_t num_read_bytes;

	int64_t constant_val;

	Instruction_Types action;
} Instruction;

bool init_capstone(cs_arch asm_arch, cs_mode asm_mode);

//necessary to convert 1 instruction to multiple instructions for simplification purposes
std::vector<Instruction> convert_asm_to_instruction(uint8_t* asm_bytes, uint32_t size);

#endif