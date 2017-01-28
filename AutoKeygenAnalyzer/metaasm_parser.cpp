#include <assert.h>

#include "metaasm_parser.hpp"
#include "ProgramState.hpp"

void load_from_mem_instr(Instruction instr, Register* tmp_reg){
	assert(instr.mem_addresses_from.size() == 1);//Load from multiple locations doesnt make sense

	bool mem_locations_exists = true;
	bool mem_locations_are_key = true;
	bool mem_locations_are_const = true;
	bool mem_locations_are_accum;

	//generate actions defining accesing each individual byte
	std::vector<Action> memory_load_bytes = std::vector<Action>(instr.num_read_bytes);
	for (uint8_t i = 0; i < instr.num_read_bytes; i++){
		Action from_address_w_offset = instr.mem_addresses_from[0];
		Action act_addi;
		Init_Action(&act_addi, ADD, CONSTANT, i);
		from_address_w_offset.actions.push_back(act_addi);

		memory_load_bytes[i] = from_address_w_offset;

		//check this byte exists as memory location
		mem_locations_exists &= (current_program_state.memory_locations.count(from_address_w_offset)>0);
		//check this byte is a key
		if (mem_locations_exists){
			//FIXME: problem if loading from half key, half other stuff
			mem_locations_are_key &= current_program_state.memory_locations[from_address_w_offset].action_chain.size() == 1 &&
				current_program_state.memory_locations[from_address_w_offset].action_chain[0].storage == KEY_DATA;
			for (size_t j = 0; j < current_program_state.memory_locations[from_address_w_offset].action_chain.size(); j++){
				mem_locations_are_const &= (current_program_state.memory_locations[from_address_w_offset].action_chain[j].storage == CONSTANT);
			}
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
			Init_Action(&act, LOAD, CONSTANT, 0/*TODO*/);
			current_program_state.memory_locations[memory_load_bytes[i]].action_chain.push_back(act);
		}

		Action act;
		Init_Action(&act, LOAD, CONSTANT, 0/*TODO*/);
		if (instr.generate_tmp_register){
			tmp_reg->action_chain.clear();
			tmp_reg->action_chain.push_back(act);
		}
		else{
			current_program_state.registers[instr.register_i_to].action_chain.clear();
			current_program_state.registers[instr.register_i_to].action_chain.push_back(act);
		}
	}
	//if locations are known and marked as key
	else if (mem_locations_exists && mem_locations_are_key){
		//create array for the key variable indexes
		std::vector<size_t> key_byte_variable_indexs;
		for (uint8_t i = 0; i < instr.num_read_bytes; i++){
			//we know that action_chain.size() == 1 and action_chain[0].storage == KEY_DATA, since mem_locations_are_key.
			key_byte_variable_indexs.push_back(current_program_state.memory_locations[memory_load_bytes[i]].action_chain[0].key_byte_variables_i[0]);
		}

		//since we're loading from a pure key, we can just reset the register
		Action act;
		Init_Action(&act, LOAD, KEY_DATA, key_byte_variable_indexs);
		if (instr.generate_tmp_register){
			tmp_reg->action_chain.clear();
			tmp_reg->action_chain.push_back(act);
		}
		else{
			current_program_state.registers[instr.register_i_to].action_chain.clear();
			current_program_state.registers[instr.register_i_to].action_chain.push_back(act);
		}
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
		if (instr.generate_tmp_register){
			tmp_reg->action_chain.clear();
			tmp_reg->action_chain.push_back(act_imm);
		}
		else{
			current_program_state.registers[instr.register_i_to].action_chain.clear();
			current_program_state.registers[instr.register_i_to].action_chain.push_back(act_imm);
		}
	}
	//if its an accumulator
	/*example
	key[0]												  key[1]												key[2]

	{load,key_val,0}									  {load,key_val,1}										{load,key_val,2}
	{load,key_val,0},{add,const,1}						  {load,key_val,1},{add,const,2}						{load,key_val,2},{add,const,3}

	{{load,key_val,0},{add,const,1}}, {lshift, accum, 0}, {{load,key_val,1},{add,const,2}}, {lshift, accum, 8}, {{load,key_val,2},{add,const,3}}, {lshift, accum, 16}
	*/
	else if (mem_locations_exists && mem_locations_are_accum){
		std::vector<Action> directed_chain;
		if (instr.generate_tmp_register){
			directed_chain = tmp_reg->action_chain;
		}
		else{
			directed_chain = current_program_state.registers[instr.register_i_to].action_chain;
		}

		//load all the loaded bytes action chains into the register's action chain
		directed_chain.clear();

		for (uint8_t i = 0; i < instr.num_read_bytes; i++){
			Action act;
			Init_Action(&act, LOAD, current_program_state.memory_locations[memory_load_bytes[i]].action_chain);
			directed_chain.push_back(act);
			Action act_shift;
			Init_Action(&act_shift, LEFT_SHIFT, ACCUMULATOR, (i * 8));
			directed_chain.push_back(act_shift);
		}
	}
	//??? Dunno
	else{
		assert(false);
	}
}

void mov_instr(Instruction instr, Register* tmp_reg){
	Action act;
	Init_Action(&act, LOAD, CONSTANT, instr.constant_val);
	//immediate into register
	if (instr.register_i_to != -1){
		current_program_state.registers[instr.register_i_to].action_chain.clear();
		current_program_state.registers[instr.register_i_to].action_chain.push_back(act);
	}
	else if (instr.generate_tmp_register){
		tmp_reg->action_chain.clear();
		tmp_reg->action_chain.push_back(act);
	}
	//immediate into memory
	else if (instr.num_read_bytes > 0){
		for (uint8_t i = 0; i < instr.num_read_bytes; i++){
			//modify const for single byte
			uint64_t mask = 0xFF << (i * 8);
			act.const_value = ((act.const_value & mask) >> (i * 8));//modify constant for the byte distrubution (select a single byte)

			//generate location
			Action from_address_w_offset = instr.mem_address_to;
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
}

void action_instr(Instruction* instr){
	std::vector<Action> from_action_history = std::vector<Action>();

	//clone the from register's action chain
	for (size_t i = 0; i < instr->mem_addresses_from.size(); i++){
		Register tmp;
		Instruction load;
		load.generate_tmp_register = true;
		load.mem_addresses_from = { instr->mem_addresses_from[i] };
		load.num_read_bytes = instr->num_read_bytes;
		load.action = LOAD;
		load_from_mem_instr(load, &tmp);

		Action act;
		Init_Action(&act, instr->action, tmp.action_chain);
		from_action_history.push_back(act);
	}
	for (size_t i = 0; i < instr->register_i_from.size(); i++){
		Action act;
		Init_Action(&act, instr->action, current_program_state.registers[instr->register_i_from[i]].action_chain);
		from_action_history.push_back(act);
	}

	//include the constant
	if (instr->constant_val_has){
		Action act;
		Init_Action(&act, instr->action, CONSTANT, instr->constant_val);
		from_action_history.push_back(act);
	}

	//copy the combined history into to register
	Action act;
	Init_Action(&act, instr->action, from_action_history);
	current_program_state.registers[instr->register_i_to].action_chain.push_back(act);
}