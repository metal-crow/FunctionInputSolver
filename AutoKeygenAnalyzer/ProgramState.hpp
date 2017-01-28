#ifndef PROGRAMSTATE_H
#define PROGRAMSTATE_H

#include <unordered_map>
#include <vector>

#include "Register.hpp"
#include "Action.hpp"
#include "Instruction.hpp"

//state of CPU. Stores registers and mem locations (registers)
typedef struct {
	std::vector<Register> registers;
	//since a memory location can be defined by a register value, the location is represented as an action chain
	//each memory location only represents a single byte.
	std::unordered_map<Action, Register, ActionHash, ActionCompare> memory_locations;
} Current_Program_State;

extern Current_Program_State current_program_state;

#endif