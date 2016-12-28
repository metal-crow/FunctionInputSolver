#include "Register.hpp"

Register::Register(){};
void Register::reset(){
	action_chain.clear();
}
void Register::add_action(Action act){
	action_chain.push_back(act);
}