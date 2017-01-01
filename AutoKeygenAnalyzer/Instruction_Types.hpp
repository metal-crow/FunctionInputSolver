#ifndef INSTRUCTIONTYPES_H
#define INSTRUCTIONTYPES_H

//Defines what each instruction is doing. 
typedef enum {
	INVALID_OPERATION,
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

#endif