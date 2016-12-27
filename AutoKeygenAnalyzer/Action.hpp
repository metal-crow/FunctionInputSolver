#ifndef ACTION_H
#define ACTION_H

#include <stdint.h>
#include <assert.h>
#include <vector>

#include "Instruction.hpp"

//What this register/mem location is loaded with
typedef enum {
	KEY_DATA,
	ACCUMULATOR,//any modified key data in general.
	CONSTANT
} STORAGE_OPTION;


//what is done to the register by an instruction
class Action{
public:
	Action(Instruction_Types op, STORAGE_OPTION stor, size_t variable);
	Action(Instruction_Types op, STORAGE_OPTION stor, uint64_t const_v);
	Action(Instruction_Types op, std::vector<Action> prev_actions);
	Instruction_Types operation;
	STORAGE_OPTION storage;

	//these are mutually exclusive
	size_t key_byte_variable_i;
	uint64_t const_value;
	std::vector<Action> actions;//used if these action must be interprited in isolation
};
Action::Action(Instruction_Types op, STORAGE_OPTION stor, size_t variable){
	assert(stor != CONSTANT);
	operation = op;
	storage = stor;
	key_byte_variable_i = variable;
}
Action::Action(Instruction_Types op, STORAGE_OPTION stor, uint64_t const_v){
	assert(stor == CONSTANT);
	operation = op;
	storage = stor;
	const_value = const_v;
}
Action::Action(Instruction_Types op, std::vector<Action> prev_actions){
	operation = op;
	actions = prev_actions;
}


#endif