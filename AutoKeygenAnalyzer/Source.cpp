#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <unicorn/unicorn.h>

#include "Instruction.hpp"
#include "Action.hpp"
#include "Register.hpp"
#include "ProgramState.hpp"


static std::vector<Action> key_byte_variables;//defines each byte of the key by the action(s) taken to retrieve it

void create_new_variable_for_key_byte(Action* act){
	act->key_byte_variables_i.push_back(key_byte_variables.size());
	key_byte_variables.push_back(*act);
}

size_t find_variable_i_for_key_byte(Action* act){
	for (size_t i = 0; i < key_byte_variables.size(); i++){
		if (EQL_Action(act, &key_byte_variables[i])){
			return i;
		}
	}
	key_byte_variables.push_back(*act);
	return key_byte_variables.size() - 1;
}


void convert_mem_instruction_into_single_byte(Action* from_address_w_offset, size_t byte_i){
	//TODO this must handle 500+1 == 501+0 == 499+2 == eax+1 == {eax+1}+0, so consolidate constants 
	Action act;
	Init_Action(&act, ADD, CONSTANT, byte_i);
	from_address_w_offset->actions.push_back(act);
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
	uint8_t input_function_codebytes[8] = { 0x89, 0x18, 0x83, 0xC0, 0x01, 0x89, 0x48, 0x0A };

	for (size_t i = X86_REG_AH; i < X86_REG_ENDING/*TODO NUM REGISTERS*/; i++){
		Register reg;
		current_program_state.registers.push_back(reg);
	}

	//bootstrap by action_chain.push_back(KEY_DATA, LOAD) to the registers/memlocations that have key
	for (key_locations){
		Action key_boot_action;
		Init_Action(&key_boot_action, LOAD, KEY_DATA, -1);
		create_new_variable_for_key_byte(&key_boot_action);
		if (is_register){
			current_program_state.registers[key_location].action_chain.push_back(key_boot_action);
		}
		//this is every byte, no larger
		else if (is_memory){
			current_program_state.memory_locations[key_location] = {};
			current_program_state.memory_locations[key_location].action_chain.push_back(key_boot_action);
		}
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
			{
				bool mem_locations_exists = true;
				bool mem_locations_are_key = true;
				bool mem_locations_are_const = true;
				bool mem_locations_are_accum;

				//generate actions defining accesing each individual byte
				std::vector<Action> memory_load_bytes = std::vector<Action>(instr.num_read_bytes);
				for (uint8_t i = 0; i < instr.num_read_bytes; i++){
					Action from_address_w_offset = instr.mem_address_from;
					convert_mem_instruction_into_single_byte(&from_address_w_offset, i);

					memory_load_bytes.push_back(from_address_w_offset);

					//check this byte exists as memory location
					mem_locations_exists &= current_program_state.memory_locations.count(from_address_w_offset);
					//check this byte is a key
					if (mem_locations_exists){
						//FIXME: problem if loading from half key, half other stuff
						mem_locations_are_key &= current_program_state.memory_locations[from_address_w_offset].action_chain.size() == 1 && 
												 current_program_state.memory_locations[from_address_w_offset].action_chain[0].storage == KEY_DATA;
						mem_locations_are_const &= current_program_state.memory_locations[from_address_w_offset].action_chain.size() == 1 &&
												   current_program_state.memory_locations[from_address_w_offset].action_chain[0].storage == CONSTANT;
					}
				}
				mem_locations_are_accum = !mem_locations_are_key && !mem_locations_are_const;

				//if mem locations arn't known to us, it can't be a key (since key mem/locations created on init)
				if (!mem_locations_exists){
					//only option must be this load is some constant/bootstrap value for key verify

					for (uint8_t i = 0; i < instr.num_read_bytes; i++){
						current_program_state.memory_locations[memory_load_bytes[i]] = {};
						Action act;
						//store in little endian order
						uint64_t mask = 0xFF << (i * 8);
						int64_t maskd_and_reshifted_imm = ((instr.constant_val & mask) >> (i * 8));//modify constant for the byte distrubution (select a single byte)
						Init_Action(&act, LOAD, CONSTANT, maskd_and_reshifted_imm);
						current_program_state.memory_locations[memory_load_bytes[i]].action_chain.push_back(act);
					}

					Action act;
					Init_Action(&act, LOAD, CONSTANT, instr.constant_val);
					current_program_state.registers[instr.register_i_to].action_chain.clear();
					current_program_state.registers[instr.register_i_to].action_chain.push_back(act);
				}
				//if locations are known and marked as key
				else if (mem_locations_exists && mem_locations_are_key){		
					//create array for the key variable indexes
					std::vector<size_t> key_byte_variable_indexs;
					for (uint8_t i = 0; i < instr.num_read_bytes; i++){
						key_byte_variable_indexs.push_back(find_variable_i_for_key_byte(&memory_load_bytes[i]));
					}

					//since we're loading from a pure key, we can just reset the register
					current_program_state.registers[instr.register_i_to].action_chain.clear();
					Action act;
					Init_Action(&act, LOAD, KEY_DATA, key_byte_variable_indexs);
					current_program_state.registers[instr.register_i_to].action_chain.push_back(act);
				}
				//if its a known constant
				else if (mem_locations_exists && mem_locations_are_const){
					Action act_imm;
					Init_Action(&act_imm, LOAD, CONSTANT, 0);
					//convert the bytes in memory to full load
					for (uint8_t i = 0; i < instr.num_read_bytes; i++){
						//little endian load
						act_imm.const_value |= (current_program_state.memory_locations[memory_load_bytes[i]].action_chain[0].const_value << (i * 8));
					}
					//clear register and load constant
					current_program_state.registers[instr.register_i_to].action_chain.clear();
					current_program_state.registers[instr.register_i_to].action_chain.push_back(act_imm);
				}
				//if its an accumulator
				else if (mem_locations_exists && mem_locations_are_accum){
					//load all the loaded bytes action chains into the register's action chain
					current_program_state.registers[instr.register_i_to].action_chain.clear();

					for (uint8_t i = 0; i < instr.num_read_bytes; i++){
						Action act;
						Init_Action(&act, LOAD, current_program_state.memory_locations[memory_load_bytes[i]].action_chain);
						current_program_state.registers[instr.register_i_to].action_chain.push_back(act);
						Action act_shift;
						Init_Action(&act_shift, LEFT_SHIFT, ACCUMULATOR, (i*8));
						current_program_state.registers[instr.register_i_to].action_chain.push_back(act_shift);
					}
				}
				//??? Dunno
				else{
					assert(false);
				}
				break;
			}

			//moving an immediate means this register's history is reset, and it is only a constant
			case MOVE:
			{
				Action act;
				Init_Action(&act, LOAD, CONSTANT, instr.constant_val);
				//immediate into register
				if (instr.register_i_to != -1){
					current_program_state.registers[instr.register_i_to].action_chain.clear();
					current_program_state.registers[instr.register_i_to].action_chain.push_back(act);
				}
				//immediate into memory
				else if (instr.num_read_bytes > 0){
					for (uint8_t i = 0; i < instr.num_read_bytes; i++){
						//modify const for single byte
						uint64_t mask = 0xFF << (i * 8);
						act.const_value = ((act.const_value & mask) >> (i * 8));//modify constant for the byte distrubution (select a single byte)

						//generate location
						Action from_address_w_offset = instr.mem_address_from;
						convert_mem_instruction_into_single_byte(&from_address_w_offset, i);

						//save const action to location
						current_program_state.memory_locations[from_address_w_offset].action_chain.clear();
						current_program_state.memory_locations[from_address_w_offset].action_chain.push_back(act);
					}
				}
				else{
					assert(false);//dont know what happened here
				}
				break;
			}

			//copy the register and its history into mem
			case STORE:
			{
				if (!current_program_state.memory_locations.count(instr.mem_address_to)){
					current_program_state.memory_locations[instr.mem_address_to] = {};
				}
				assert(instr.register_i_from.size() == 1);
				memcpy(&current_program_state.memory_locations[instr.mem_address_to], &current_program_state.registers[instr.register_i_from[0]], sizeof(Register));
				break;
			}

			case ADD:
				copy_from_action_histories(&instr);
				break;

			case SUBTRACT:
				copy_from_action_histories(&instr);
				break;

			case MULTIPLY:
				copy_from_action_histories(&instr);
				break;

			case DIVIDE:
				copy_from_action_histories(&instr);
				break;

			case AND:
				copy_from_action_histories(&instr);
				break;

			case OR:
				copy_from_action_histories(&instr);
				break;

			case XOR:
				copy_from_action_histories(&instr);
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