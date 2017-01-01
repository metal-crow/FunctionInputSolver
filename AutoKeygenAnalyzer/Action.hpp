#ifndef ACTION_H
#define ACTION_H

#include <stdint.h>
#include <vector>

#include "Instruction_Types.hpp"

//What this register/mem location is loaded with
typedef enum {
	INVALID_STORAGE,
	KEY_DATA,
	ACCUMULATOR,//any modified key data in general.
	CONSTANT
} STORAGE_OPTION;

typedef struct Action Action;

//what is done to the register by an instruction
struct Action{
	Instruction_Types operation = INVALID_OPERATION;
	STORAGE_OPTION storage = INVALID_STORAGE;

	//these are mutually exclusive
	size_t key_byte_variable_i = -1;
	int64_t const_value = -1;
	std::vector<Action> actions;//used if these action must be interprited in isolation
};

void Init_Action(Action* action, Instruction_Types op, STORAGE_OPTION stor, int64_t arg);
void Init_Action(Action* action, Instruction_Types op, std::vector<Action> prev_actions);


//used by the memory map array to compare actions
bool EQL_Action(const Action* a1, const Action* a2);
struct ActionCompare
{
	bool operator() (const Action& a1, const Action& a2) const{
		return EQL_Action(&a1, &a2);
	}
};

#endif