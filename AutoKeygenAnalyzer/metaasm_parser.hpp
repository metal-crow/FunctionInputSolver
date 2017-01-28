#ifndef METAASM_PARSER_H
#define METAASM_PARSER_H

#include "Instruction.hpp"
#include "Register.hpp"

//given a LOAD instruction, move into the specified register
void load_from_mem_instr(Instruction instr, Register* tmp_reg);

//given a MOV instruction, load the constant in
//moving an immediate in means this register's history is reset, since it is now a constant
void mov_instr(Instruction instr, Register* tmp_reg);

//given an instruction, copy the input registers/what stored in input memory's action chains in.
void action_instr(Instruction* instr);

#endif