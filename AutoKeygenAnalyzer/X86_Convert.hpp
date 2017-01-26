#ifndef X86_CONVERT_H
#define X86_CONVERT_H

#include <capstone.h>
#include "Instruction.hpp"

void interpret_x86(std::vector<Instruction>* instructions, cs_insn *decod_instr);

#endif