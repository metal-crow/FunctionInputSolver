#include <stdio.h>
#include <stdint.h>
#include <unordered_map>
#include <set>
#include <assert.h>

#include <unicorn/unicorn.h>

#include "Instruction.hpp"
#include "Action.hpp"
#include "Register.hpp"


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


// callback for tracing instruction
static void hook_instruction(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);


// memory address where emulation starts
#define ADDRESS 0x1000000

int main(void){
	//read in assembly function
	/*
	sum=0
	for i=0;i<strlen(key);i++
	sum+=inputstr[i]
	return sum==1337
	*/
	uint8_t input_function_codebytes[8] = { 0x89, 0xD8/*0x18 */ };

	//bootstrap by action_chain.push_back(KEY_DATA, LOAD) to the registers/memlocations that have key
	for (size_t i = 0; i < 6/*TODO NUM REGISTERS*/; i++){
		current_program_state.registers.push_back(Register());
	}

	uc_engine *uc;
	uc_err err;
	uc_hook trace;

	// Initialize capstone disassembler in X86-32bit mode
	assert(init_capstone(CS_ARCH_X86, CS_MODE_32));

	// Initialize emulator in X86-32bit mode
	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if (err != UC_ERR_OK) {
		printf("Failed on uc_open() with error returned: %u\n", err);
		return -1;
	}

	// map 2MB memory for this emulation
	uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

	// write machine code to be emulated to memory
	if (uc_mem_write(uc, ADDRESS, input_function_codebytes, sizeof(input_function_codebytes))) {
		printf("Failed to write emulation code to memory, quit!\n");
		return -1;
	}

	// tracing all instruction by having @begin > @end
	uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_instruction, NULL, 1, 0);

	// emulate code in infinite time & unlimited instructions
	err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(input_function_codebytes), 0, 0);
	if (err) {
		printf("Failed on uc_emu_start() with error returned %u: %s\n",
			   err, uc_strerror(err));
	}

	// now print out some registers
	printf("Emulation done. Below is the CPU context\n");
	int r_ecx, r_edx;
	uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
	uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
	printf(">>> ECX = 0x%x\n", r_ecx);
	printf(">>> EDX = 0x%x\n", r_edx);

	uc_close(uc);
}

static void hook_instruction(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	int eflags;
	printf(">>> Tracing instruction at 0x%x, instruction size = 0x%d\n", address, size);

	uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
	printf(">>> --- EFLAGS is 0x%x\n", eflags);

	// Uncomment below code to stop the emulation using uc_emu_stop()
	// if (address == 0x1000009)
	//    uc_emu_stop(uc);

	//interprite the function with unicorn, and build action log as we go
	//convert any instructions with immediates to a MOVE then the instruction
	/*
	sum=0
	sum+=key[0]
	sum+=key[1]
	sum+=key[2]
	return sum==1337
	*/
	
	uint8_t asm_bytes[15];//An x86-64 instruction may be at most 15 bytes in length
	if (uc_mem_read(uc, address, &asm_bytes, size)){
		printf("Failed to read instruction, quit!\n");
		assert(false);
	}
	std::vector<Instruction> instructions = convert_asm_to_instruction(asm_bytes, size);

	for (size_t i = 0; i < instructions.size(); i++){
		Instruction instr = instructions[i];
		switch (instr.action){
			case LOAD:
				//if mem location isn't known to us, it can't be a key (since key mem/location created on init)
				if (!current_program_state.memory_locations.count(instr.mem_address_from)){
					//only option must be this load is some constant/bootstrap value for key verify
					current_program_state.memory_locations[instr.mem_address_from] = Register();
					current_program_state.memory_locations[instr.mem_address_from].add_action(Action(LOAD, CONSTANT, /*instr.constant_val*/0));

					current_program_state.registers[instr.register_i_to].reset();
					current_program_state.registers[instr.register_i_to].add_action(Action(LOAD, CONSTANT, /*instr.constant_val*/0));
				}
				//if location is known and is marked as key
				else if (current_program_state.memory_locations.count(instr.mem_address_from) &&
						 current_program_state.memory_locations[instr.mem_address_from].action_chain.size() == 1 &&
						 current_program_state.memory_locations[instr.mem_address_from].action_chain[0].storage == KEY_DATA)
				{
					//get key bytes variable
					std::vector<uint64_t> key_bytes = std::vector<uint64_t>(instr.num_read_bytes);
					for (uint8_t i = 0; i < instr.num_read_bytes; i++){
						assert(current_program_state.memory_locations[i + instr.mem_address_from].action_chain.size() == 1 &&
							   current_program_state.memory_locations[i + instr.mem_address_from].action_chain[0].storage == KEY_DATA);//TODO issue if reading half key half other stuff
						key_bytes.push_back(i + instr.mem_address_from);
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
				current_program_state.memory_locations[instr.register_i_to].add_action(Action(LOAD, CONSTANT, /*instr.constant_val*/0));
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

			case CMP_JMP:
				assert(instr.register_i_from.size() == 1);
				current_program_state.registers[instr.register_i_to].compared = true;
				current_program_state.registers[instr.register_i_from[0]].compared = true;
				//TODO for every compare break, convert action log to poly equation, and solve
				break;
		}
	}
		
	//convert action chain to equations
	for (size_t i = 0; i < current_program_state.registers.size(); i++){
		Register reg = current_program_state.registers[i];
		//if (reg.compared){
		//
		//}
	}
	
	//try and solve
}