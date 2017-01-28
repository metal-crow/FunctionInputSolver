#ifndef INSTRUCTIONS_H
#define INSTRUCTIONS_H

#include <stdint.h>
#include <vector>

#include <capstone.h>

#include "Action.hpp"
#include "Instruction_Types.hpp"

typedef struct Instruction_S {
	//Mutually exclusive
	int32_t register_i_to = -1;
	bool generate_tmp_register = false;
	Action mem_address_to;

	//Mutually exclusive
	std::vector<uint32_t> register_i_from;
	std::vector<Action> mem_addresses_from;
	int64_t constant_val;

	bool constant_val_has = false;

	uint8_t num_read_bytes = 0;//size of mem ptr (if mem read from)

	Instruction_Types action = INVALID_OPERATION;
} Instruction;

bool init_capstone(cs_arch asm_arch, cs_mode asm_mode);

//necessary to convert 1 instruction to multiple instructions for simplification purposes
std::vector<Instruction> convert_asm_to_instruction(uint8_t* asm_bytes, uint32_t size);

#endif