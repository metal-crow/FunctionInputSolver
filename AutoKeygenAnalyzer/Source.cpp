#include <stdio.h>
#include <stdint.h>
#include <unordered_map>
#include <cassert>

#include "Instruction.h"

static std::vector<std::vector<uint8_t>> key_byte_variables;//this contains unique variables (a section of the key bytes). If two key byte sections are the same, they are same vairable.

size_t find_variable_i_for_key_bytes(std::vector<uint8_t> input_vars){
	for (size_t i = 0; i < key_byte_variables.size(); i++){
		if (input_vars == key_byte_variables[i]){
			return i;
		}
	}
	key_byte_variables.push_back(input_vars);
	return key_byte_variables.size() - 1;
}

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
		Action(std::vector<Action> prev_actions);
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
Action::Action(std::vector<Action> prev_actions){
	actions = prev_actions;
}


//a register. Stores history of actions to it
class Register{
	public:
		Register();
		void reset(void);
		void add_action(Action act);

		std::vector<Action> action_chain;//history of actions to this register. This is the main principle
};
Register::Register(){};
void Register::reset(){
	action_chain.clear();
}
void Register::add_action(Action act){
	action_chain.push_back(act);
}

//state of CPU. Stores registers and mem locations (registers)
typedef struct {
	Register* registers;
	std::unordered_map<uint64_t, Register> memory_locations;
} Current_Program_State;


static Current_Program_State current_program_state;


int main(void){
	printf("hello");

	//read in assembly function
	/*
	sum=0
	for i=0;i<strlen(key);i++
		sum+=inputstr[i]
	return sum==1337
	*/

	//find loop(s) over asm input string (key)

	//loop (optional, usually we know key length at start)
		//unroll for current key length (n)
		//(TODO) Handle self modifying code here (past and future alterations)
		/*
		sum=0
		sum+=key[0]
		sum+=key[1]
		sum+=key[2]
		return sum==1337
		*/

		//bootstrap by action_chain.push_back(KEY_DATA, LOAD) to the registers/memlocations that have key
	
		//convert to Polynomial
		//once we have finished interpriting, check all registers/mem locations, and use their action log to build poly equation
		/*key[0]+key[1]+key[2]=1337*/

	for (uint64_t i = 0; i < function_length;i++){
		Instruction instr = unrolled_function[i];

		switch (instr.action){
			case LOAD:
				//if mem location isn't known to us
				if (!current_program_state.memory_locations.count(instr.mem_address_from)){
					//will never be key if doesnt exist, key mem/location created on init
					//only option must be this load is some constant/bootstrap value for key verify
					current_program_state.memory_locations[instr.mem_address_from] = Register();
					current_program_state.memory_locations[instr.mem_address_from].add_action(Action(LOAD, CONSTANT, constant_val));
				}

				//copy the register and its history from mem
				memcpy(&current_program_state.registers[instr.register_i_to], &current_program_state.memory_locations[instr.mem_address_from], sizeof(Register));
				break;
				
			//moving an immediate means this register's history is reset, and it is only a constant
			case MOVE:
				current_program_state.registers[instr.register_i_to].reset();
				current_program_state.memory_locations[instr.register_i_to].add_action(Action(MOVE, CONSTANT, constant_val));
				break;

			//copy the register and its history into mem
			case STORE:
				if (!current_program_state.memory_locations.count(instr.mem_address_to)){
					current_program_state.memory_locations[instr.mem_address_to] = Register();
				}
				memcpy(&current_program_state.memory_locations[instr.mem_address_to], &current_program_state.registers[instr.register_i_from.at(0)], sizeof(Register));
				break;

			case ADD:
				//malloc action history array
				std::vector<Action> from_action_history = std::vector<Action>(instr.register_i_from.size());

				//clone each from register's action chain
				for (size_t i = 0; i < instr.register_i_from.size(); i++){
					std::vector<Action> reg_i_actions = std::vector<Action>(current_program_state.registers[i].action_chain.size());
					for (size_t j = 0; j < current_program_state.registers[i].action_chain.size(); j++){
						reg_i_actions.push_back(current_program_state.registers[i].action_chain[i]);
					}
					from_action_history.push_back(Action(reg_i_actions));
				}

				//copy the combined history into to register
				current_program_state.registers[instr.register_i_to].add_action(Action(from_action_history));
				break;
		}
	}
		
		//convert action chain to equations

		//try and solve
}