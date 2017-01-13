#include <assert.h>
#include <unordered_map>
#include <queue>
#include <forward_list>

#include "Action.hpp"

void Init_Action(Action* action, Instruction_Types op, STORAGE_OPTION stor, std::vector<size_t> key_byte_variables_i){
	action->operation = op;
	action->storage = stor;
	assert(stor != CONSTANT);
	action->key_byte_variables_i = key_byte_variables_i;
}

void Init_Action(Action* action, Instruction_Types op, STORAGE_OPTION stor, int64_t constant){
	action->operation = op;
	action->storage = stor;
	assert(stor == CONSTANT);
	action->const_value = constant;
}

void Init_Action(Action* action, Instruction_Types op, std::vector<Action> prev_actions){
	action->operation = op;
	action->actions = std::vector<Action>(prev_actions);//this should copy the given vector
}



//maps the variable id to a bit in the variable_settings int
static std::unordered_map<size_t, size_t> mapping_from_variable_to_bit;

//counts numbers of variables and also created the variable to bit mapping
static uint64_t find_number_of_variables_in_action(Action* a){
	uint64_t current_bit = 0;//also doubles as counting number of variables

	std::queue<Action*> action_queue;
	action_queue.push(a);

	while (!action_queue.empty()){
		Action* act = action_queue.front();
		action_queue.pop();

		//assign bit to variables
		for (size_t i = 0; i < act->key_byte_variables_i.size(); i++){
			//ignore if we already have this variable
			if (!mapping_from_variable_to_bit.count(act->key_byte_variables_i[i])){
				mapping_from_variable_to_bit[act->key_byte_variables_i[i]] = current_bit;
				current_bit++;
			}
		}
		for (size_t i = 0; i < act->actions.size(); i++){
			action_queue.push(&act->actions[i]);
		}
	}

	return current_bit;
}

static uint8_t variable_to_binary(size_t variable, uint64_t variable_settings){
	//use the integer as a bit sequence and find this variable's chosen bit
	size_t bit_i = mapping_from_variable_to_bit[variable];

	//and out every other bit
	uint64_t result = variable_settings & ~bit_i;
	//move bit back to least sig bit (also cut off rest of bits)
	result = result >> (bit_i - 1);
	//check
	assert(result == 0 || result == 1);
	//return with upper bytes cut off
	return (uint8_t)result;
}

static int64_t solve_action_for_variable_settings(Action* act_arg, uint64_t variable_settings){
	int64_t accumulator = 0;
	//go through the action and process it

	std::forward_list<Action*> action_queue;
	action_queue.push_front(act_arg);

	while (!action_queue.empty()){
		Action* act = action_queue.front();
		action_queue.pop_front();

		//since the action array is mutually excusive with const and key_byte_variables, can put queue creation outside switch

		//insert, in order, at the front of the list
		for (size_t i = act->actions.size(); i > 0; i--){
			action_queue.push_front(&act->actions[i - 1]);
		}
		if (act->actions.size() == 0){
			switch (act->operation){
				case LOAD:
					//this needs to be reversed for ordering
					for (size_t i = act->key_byte_variables_i.size(); i > 0; i--){
						accumulator <<= 8;
						accumulator |= variable_to_binary(act->key_byte_variables_i[i - 1], variable_settings);
					}
					break;

				case MOVE:
					accumulator = act->const_value;
					break;

				case ADD:
					for (size_t i = 0; i < act->key_byte_variables_i.size(); i++){
						accumulator += variable_to_binary(act->key_byte_variables_i[i], variable_settings);
					}
					if (act->storage == CONSTANT){
						accumulator += act->const_value;
					}
					break;

				case SUBTRACT:
					for (size_t i = 0; i < act->key_byte_variables_i.size(); i++){
						accumulator -= variable_to_binary(act->key_byte_variables_i[i], variable_settings);
					}
					if (act->storage == CONSTANT){
						accumulator -= act->const_value;
					}
					break;

				case MULTIPLY:
					for (size_t i = 0; i < act->key_byte_variables_i.size(); i++){
						accumulator *= variable_to_binary(act->key_byte_variables_i[i], variable_settings);
					}
					if (act->storage == CONSTANT){
						accumulator *= act->const_value;
					}
					break;

				case DIVIDE:
					for (size_t i = 0; i < act->key_byte_variables_i.size(); i++){
						accumulator /= variable_to_binary(act->key_byte_variables_i[i], variable_settings);
					}
					if (act->storage == CONSTANT){
						accumulator /= act->const_value;
					}
					break;

				case AND:
					for (size_t i = 0; i < act->key_byte_variables_i.size(); i++){
						accumulator &= variable_to_binary(act->key_byte_variables_i[i], variable_settings);
					}
					if (act->storage == CONSTANT){
						accumulator &= act->const_value;
					}
					break;

				case OR:
					for (size_t i = 0; i < act->key_byte_variables_i.size(); i++){
						accumulator |= variable_to_binary(act->key_byte_variables_i[i], variable_settings);
					}
					if (act->storage == CONSTANT){
						accumulator |= act->const_value;
					}
					break;

				case XOR:
					for (size_t i = 0; i < act->key_byte_variables_i.size(); i++){
						accumulator ^= variable_to_binary(act->key_byte_variables_i[i], variable_settings);
					}
					if (act->storage == CONSTANT){
						accumulator ^= act->const_value;
					}
					break;

				case BIT_INVERT:
					accumulator = ~accumulator;
					break;

				case LEFT_SHIFT:
					for (size_t i = 0; i < act->key_byte_variables_i.size(); i++){
						accumulator <<= variable_to_binary(act->key_byte_variables_i[i], variable_settings);
					}
					if (act->storage == CONSTANT){
						accumulator <<= act->const_value;
					}
					break;

				case RIGHT_SHIFT:
					for (size_t i = 0; i < act->key_byte_variables_i.size(); i++){
						accumulator >>= variable_to_binary(act->key_byte_variables_i[i], variable_settings);
					}
					if (act->storage == CONSTANT){
						accumulator >>= act->const_value;
					}
					break;

				case ABS_VAL:
					accumulator = abs(accumulator);
					break;

				default:
					break;
			}
		}
	}

	return accumulator;
}

bool EQL_Action(const Action* a1, const Action* a2){
	//TODO need this to have two actions that simplfy to the same thing be equal
	//TODO this must handle 
	//500+1 == 501+0 == 499+2
	//eax+1 == {eax+1}+0
	//eax+ebx == ebx+eax
	//{eax+1}*5 != {eax*5}+1

	/*
	for every variable
		set it to 0 (in both equations)
		solve equations see if equal
		set it to 1
		solve equations see if equal

	O(2^n). DICK.
	This works, right? (ignoring floating point)
	*/

	uint64_t num_variables_in = find_number_of_variables_in_action((Action*)a1);
	if (num_variables_in != find_number_of_variables_in_action((Action*)a2)){
		return false;
	}
	assert(num_variables_in <= sizeof(num_variables_in)*8);//TODO fix this to handle more variables (currently 64 max). Also fix this to not be 2^n

	//generate all binary combinations for n variables (as an integer)
	uint64_t num_combinations = 1 << num_variables_in; //2^num_variables
	for (uint64_t seq = 0; seq < num_combinations; seq++){
		//set the variables and solve (always do once in case theres no variables)
		int64_t result_1 = solve_action_for_variable_settings((Action*)a1, seq);
		if (result_1 != solve_action_for_variable_settings((Action*)a2, seq)){
			return false;
		}
	}

	return true;
}

size_t HASH_Action(const Action* a){
	//This has to be quick, so test two cases most likely to fail (all 1 and all 0), combine via xor 
	return (solve_action_for_variable_settings((Action*)a, (uint64_t)-1) ^ solve_action_for_variable_settings((Action*)a, 0));
}