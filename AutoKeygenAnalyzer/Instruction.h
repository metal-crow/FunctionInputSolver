#ifndef INSTRUCTIONS_H
#define INSTRUCTIONS_H

#include <stdint.h>

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
	CMP,
} Instruction_Types;

typedef struct {
	uint32_t register_i_to;
	uint32_t register_i_from1;//this is the one used for STORE
	uint32_t register_i_from2;

	uint64_t mem_address_to;
	uint64_t mem_address_from;

	Instruction_Types action;
} Instruction;

#endif