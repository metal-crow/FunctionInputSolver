#ifndef REGISTER_H
#define REGISTER_H

#include <vector>

#include "Action.hpp"

//a register. Stores history of actions to it
typedef struct Register{
	bool compared = false;
	std::vector<Action> action_chain;//history of actions to this register. This is the main principle
} Register;

#endif