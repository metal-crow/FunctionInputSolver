#include <stdio.h>
#include <stdint.h>
#include <unordered_map>
#include <set>

#include "Instruction.hpp"
#include "Action.hpp"


static std::vector<std::vector<uint64_t>> key_byte_variables;//this contains unique variables (a section of the key bytes). If two key byte sections are the same, they are same vairable.

size_t find_variable_i_for_key_bytes(std::vector<uint64_t> input_vars){
	for (size_t i = 0; i < key_byte_variables.size(); i++){
		//order does matter, but theres no way to reorder anyway
		if (input_vars == key_byte_variables[i]){
			return i;
		}
	}
	key_byte_variables.push_back(input_vars);
	return key_byte_variables.size() - 1;
}

//a register. Stores history of actions to it
class Register{
	public:
		Register();
		void reset(void);
		void add_action(Action act);

		bool compared=false;
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
	std::vector<Register> registers;
	std::unordered_map<uint64_t, Register> memory_locations;
} Current_Program_State;

static Current_Program_State current_program_state;


//given an instruction that takes from multiple registers and stores the result in 1 output register
void copy_from_action_histories(Instruction instr){
	std::vector<Action> from_action_history = std::vector<Action>(instr.register_i_from.size());

	//clone each from register's action chain
	for (size_t i = 0; i < instr.register_i_from.size(); i++){
		Register from_register = current_program_state.registers[instr.register_i_from[i]];

		std::vector<Action> reg_i_actions = std::vector<Action>(from_register.action_chain.size());
		for (size_t j = 0; j < from_register.action_chain.size(); j++){
			reg_i_actions.push_back(from_register.action_chain[j]);
		}
		from_action_history.push_back(Action(instr.action, reg_i_actions));
	}

	//copy the combined history into to register
	current_program_state.registers[instr.register_i_to].add_action(Action(instr.action, from_action_history));
}

int main(void){
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
		//also convert any instructions with immediates to a MOVE then the instruction
		//(TODO) Handle self modifying code here (past and future alterations)
		//(TODO) How to handle jmps, if statements?
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
				//if mem location isn't known to us, it can't be a key (since key mem/location created on init)
				if (!current_program_state.memory_locations.count(instr.mem_address_from)){
					//only option must be this load is some constant/bootstrap value for key verify
					current_program_state.memory_locations[instr.mem_address_from] = Register();
					current_program_state.memory_locations[instr.mem_address_from].add_action(Action(LOAD, CONSTANT, instr.constant_val));

					current_program_state.registers[instr.register_i_to].reset();
					current_program_state.registers[instr.register_i_to].add_action(Action(LOAD, CONSTANT, instr.constant_val));
				}
				//if location is known and is marked as key
				else if (current_program_state.memory_locations.count(instr.mem_address_from) && 
						 current_program_state.memory_locations[instr.mem_address_from].action_chain.size() == 1 &&
						 current_program_state.memory_locations[instr.mem_address_from].action_chain[0].storage==KEY_DATA)
				{
					//get key bytes variable
					std::vector<uint64_t> key_bytes = std::vector<uint64_t>(instr.num_read_bytes);
					for (uint8_t i = 0; i < instr.num_read_bytes; i++){
						assert(current_program_state.memory_locations[i + instr.mem_address_from].action_chain.size()==1 && 
							   current_program_state.memory_locations[i + instr.mem_address_from].action_chain[0].storage==KEY_DATA);//TODO issue if reading half key half other stuff
						key_bytes.push_back(i+instr.mem_address_from);
					}
					size_t key_bytes_var_i = find_variable_i_for_key_bytes(key_bytes);

					//since we're loading from a pure key, we can just reset the register
					current_program_state.registers[instr.register_i_to].reset();
					current_program_state.registers[instr.register_i_to].add_action(Action(LOAD, KEY_DATA, key_bytes_var_i));
				}
				//its an accumulator or constant. just copy the register and its history from mem
				else{
					memcpy(&current_program_state.registers[instr.register_i_to], &current_program_state.memory_locations[instr.mem_address_from], sizeof(Register));
				}
				break;
				
			//moving an immediate means this register's history is reset, and it is only a constant
			case MOVE:
				current_program_state.registers[instr.register_i_to].reset();
				current_program_state.memory_locations[instr.register_i_to].add_action(Action(LOAD, CONSTANT, instr.constant_val));
				break;

			//copy the register and its history into mem
			case STORE:
				if (!current_program_state.memory_locations.count(instr.mem_address_to)){
					current_program_state.memory_locations[instr.mem_address_to] = Register();
				}
				assert(instr.register_i_from.size() == 1);
				memcpy(&current_program_state.memory_locations[instr.mem_address_to], &current_program_state.registers[instr.register_i_from[0]], sizeof(Register));
				break;

			case ADD:
				copy_from_action_histories(instr);
				break;

			case SUBTRACT:
				copy_from_action_histories(instr);
				break;

			case MULTIPLY:
				copy_from_action_histories(instr);
				break;

			case DIVIDE:
				copy_from_action_histories(instr);
				break;

			case AND:
				copy_from_action_histories(instr);
				break;

			case OR:
				copy_from_action_histories(instr);
				break;

			case XOR:
				copy_from_action_histories(instr);
				break;

			case CMP:
				assert(instr.register_i_from.size() == 1);
				current_program_state.registers[instr.register_i_to].compared = true;
				current_program_state.registers[instr.register_i_from[0]].compared = true;
				break;
		}
	}
		
		//convert action chain to equations
	for (size_t i = 0; i < current_program_state.registers.size(); i++){
		Register reg = current_program_state.registers[i];
		if (reg.compared){

		}
	}
		//try and solve
}