#include "Action.hpp"

void Init_Action(Action* action, Instruction_Types op, STORAGE_OPTION stor, int64_t arg){
	action->operation = op;
	action->storage = stor;
	if (stor == CONSTANT){
		action->const_value = arg;
	}
	else{
		action->key_byte_variable_i = arg;
	}
}

void Init_Action(Action* action, Instruction_Types op, std::vector<Action> prev_actions){
	action->operation = op;
	action->actions = std::vector<Action>(prev_actions);//this should copy the given vector
}

bool EQL_Action(const Action* a1, const Action* a2){
	if (a1->operation != a2->operation){
		return false;
	}

	if (a1->actions.size() != a2->actions.size()){
		return false;
	}
	if (a1->actions.size() == 0 && a2->actions.size() == 0){
		if (a1->storage != a2->storage){
			return false;
		}
		if (a1->storage == CONSTANT){
			return (a1->const_value == a2->const_value);
		}
		else{
			return (a1->key_byte_variable_i == a2->key_byte_variable_i);
		}
	}
	//compare their recursive action subsets
	else{
		bool result = true;
		for (size_t i = 0; i < a1->actions.size(); i++){
			result &= EQL_Action(&(a1->actions[i]), &(a2->actions[i]));
		}
		return result;
	}
}