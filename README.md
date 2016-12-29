#North Star Solver

##Abstract
This program's idea originated in whether it was possible to interpret a program's serial key verfication function, and solve for a valid key (automatically keygen it).  
  
Still in early stages/research, basic idea so far:  

* Take in an assembly function that verifies the key  
* Mark the sections of memory/registers where the unaltered input key is stored
* Interpret the function and generate a log of actions that occur to each discrete piece of data over the function
* Convert these action logs in polynomial equations
* Solve the equations