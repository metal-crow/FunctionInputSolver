#include "ProgramState.hpp"

Current_Program_State current_program_state;

void copy_from_action_histories(Instruction* instr){
	std::vector<Action> from_action_history = std::vector<Action>(instr->register_i_from.size());

	//clone each from register's action chain
	for (size_t i = 0; i < instr->register_i_from.size(); i++){
		Register from_register = current_program_state.registers[instr->register_i_from[i]];

		std::vector<Action> reg_i_actions = std::vector<Action>(from_register.action_chain.size());
		for (size_t j = 0; j < from_register.action_chain.size(); j++){
			reg_i_actions.push_back(from_register.action_chain[j]);
		}

		Action act;
		Init_Action(&act, instr->action, reg_i_actions);
		from_action_history.push_back(act);
	}

	//copy the combined history into to register
	Action act;
	Init_Action(&act, instr->action, from_action_history);
	current_program_state.registers[instr->register_i_to].action_chain.push_back(act);
}