#ifndef PROGRAMSTATE_H
#define PROGRAMSTATE_H

#include <map>
#include <vector>

#include "Register.hpp"
#include "Action.hpp"
#include "Instruction.hpp"

//state of CPU. Stores registers and mem locations (registers)
typedef struct {
	std::vector<Register> registers;
	std::map<Action, Register, ActionCompare> memory_locations;//since a memory location can be defined by a register value, the location is represented as an action chain
} Current_Program_State;

extern Current_Program_State current_program_state;

//given an instruction that takes from multiple registers and stores the result in 1 output register
void copy_from_action_histories(Instruction* instr);

#endif