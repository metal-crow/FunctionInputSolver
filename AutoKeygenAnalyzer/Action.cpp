#include "Action.hpp"

Action::Action(){}
Action::Action(Instruction_Types op, STORAGE_OPTION stor, uint64_t const_v){
	operation = op;
	storage = stor;
	if (stor == CONSTANT){
		const_value = const_v;
	}
	else{
		key_byte_variable_i = const_v;
	}
}
Action::Action(Instruction_Types op, std::vector<Action> prev_actions){
	operation = op;
	actions = prev_actions;
}