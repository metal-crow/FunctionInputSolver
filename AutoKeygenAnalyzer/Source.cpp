#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <vector>

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

// callback for tracing instruction
static void hook_instruction(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);


// memory address where emulation starts (2MB)
#define CODE_ADDRESS (2 * 1024 * 1024)
#define DATA_ADDRESS 0

int main(void){
	//read in assembly function
	/*
	sum=0
	for i=0;i<strlen(key);i++
	sum+=inputstr[i]
	return sum==1337
	*/

	/*
	//esp{0,1,2} is key bytes, checksum for them is in eax
	add eax, 500
	mov eax, byte ptr [esp]
	add eax, byte ptr [esp+1]
	add eax, byte ptr [esp+2]
	*/
	uint8_t input_function_codebytes[] = { 0x05, 0xF4, 0x01, 0x00, 0x00, 0x8A, 0x04, 0x24, 0x02, 0x44, 0x24, 0x01, 0x02, 0x44, 0x24, 0x02 };

	//initalize all the (combined) registers.
	for (size_t i = 0; i < 300/*TODO NUM REGISTERS*/; i++){
		Register reg;
		current_program_state.registers.push_back(reg);
	}

	//bootstrap by action_chain.push_back(KEY_DATA, LOAD) to the registers/memlocations that have key

	std::vector<size_t> register_key_locations = {};

	//dont need to set any of the info variables (key, constant, action) for these, since register exists as preexisting item
	Action esp_mem_0;
	Init_Action(&esp_mem_0, LOAD, ACCUMULATOR);

	Action mem_plus_1;
	Init_Action(&mem_plus_1, ADD, CONSTANT, 1);
	Action esp_mem_1;
	Init_Action(&esp_mem_1, LOAD, { mem_plus_1 });

	Action mem_plus_2;
	Init_Action(&mem_plus_2, ADD, CONSTANT, 2);
	Action esp_mem_2;
	Init_Action(&esp_mem_2, LOAD, { mem_plus_2 });

	std::vector<Action> memory_key_locations = { esp_mem_0, esp_mem_1, esp_mem_2 };//this is every byte, no larger

	for (size_t i = 0; i < register_key_locations.size(); i++){
		Action key_boot_action;
		Init_Action(&key_boot_action, LOAD, KEY_DATA);
		create_new_variable_for_key_byte(&key_boot_action);

		current_program_state.registers[register_key_locations[i]].action_chain.push_back(key_boot_action);
	}
	for (size_t i = 0; i < memory_key_locations.size(); i++){
		Action key_boot_action;
		Init_Action(&key_boot_action, LOAD, KEY_DATA);
		create_new_variable_for_key_byte(&key_boot_action);

		current_program_state.memory_locations[memory_key_locations[i]] = {};
		current_program_state.memory_locations[memory_key_locations[i]].action_chain.push_back(key_boot_action);
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
	uc_mem_map(uc, CODE_ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);
	// map 2MB memory for data
	uc_mem_map(uc, DATA_ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

	// write machine code to be emulated to memory
	if (uc_mem_write(uc, CODE_ADDRESS, input_function_codebytes, sizeof(input_function_codebytes))) {
		printf("Failed to write emulation code to memory, quit!\n");
		return -1;
	}

	// tracing all instruction by having @begin > @end
	uc_hook_add(uc, &trace, UC_HOOK_CODE, hook_instruction, NULL, 1, 0);

	//default all registers to 0
	for (int i = X86_REG_AH; i < X86_REG_ENDING/*TODO NUM REGISTERS*/; i++){
		int reg = 0;
		uc_reg_write(uc, i, &reg);
	}

	// emulate code in infinite time & unlimited instructions
	err = uc_emu_start(uc, CODE_ADDRESS, CODE_ADDRESS + sizeof(input_function_codebytes), 0, 0);
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
	//TODO what if just cut out the Middle man: my generic Instruction? That makes this too interconnected maybe.
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
					Action act_addi;
					Init_Action(&act_addi, ADD, CONSTANT, i);
					from_address_w_offset.actions.push_back(act_addi);

					memory_load_bytes.push_back(from_address_w_offset);

					//check this byte exists as memory location
					mem_locations_exists &= (current_program_state.memory_locations.count(from_address_w_offset)>0);
					//check this byte is a key
					if (mem_locations_exists){
						//FIXME: problem if loading from half key, half other stuff
						mem_locations_are_key &= current_program_state.memory_locations[from_address_w_offset].action_chain.size() == 1 && 
												 current_program_state.memory_locations[from_address_w_offset].action_chain[0].storage == KEY_DATA;
						mem_locations_are_const &= current_program_state.memory_locations[from_address_w_offset].action_chain.size() == 1 &&
												   current_program_state.memory_locations[from_address_w_offset].action_chain[0].storage == CONSTANT;
						//can't check for accumulator here since action_chain can be >1, so don't know where to look
					}
				}
				mem_locations_are_accum = !mem_locations_are_key && !mem_locations_are_const;

				//if mem locations arn't known to us, it can't be a key (since key mem/locations created on init)
				if (!mem_locations_exists){
					//only option must be this load is some constant/bootstrap value for key verify. mark each memory byte
					for (uint8_t i = 0; i < instr.num_read_bytes; i++){
						current_program_state.memory_locations[memory_load_bytes[i]] = {};
						Action act;
						Init_Action(&act, LOAD, CONSTANT, the_constant_currently_in_memory_location);
						current_program_state.memory_locations[memory_load_bytes[i]].action_chain.push_back(act);
					}

					Action act;
					Init_Action(&act, LOAD, CONSTANT, the_constant_currently_in_memory_locations);
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
				/*example
				key[0]												  key[1]												key[2]

				{load,key_val,0}									  {load,key_val,1}										{load,key_val,2}
				{load,key_val,0},{add,const,1}						  {load,key_val,1},{add,const,2}						{load,key_val,2},{add,const,3}

				{{load,key_val,0},{add,const,1}}, {lshift, accum, 0}, {{load,key_val,1},{add,const,2}}, {lshift, accum, 8}, {{load,key_val,2},{add,const,3}}, {lshift, accum, 16}
				*/
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
						Action act_addi;
						Init_Action(&act_addi, ADD, CONSTANT, i);
						from_address_w_offset.actions.push_back(act_addi);

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
				assert(instr.register_i_from.size() == 1);
				current_program_state.memory_locations[instr.mem_address_to] = current_program_state.registers[instr.register_i_from[0]];
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