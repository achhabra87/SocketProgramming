






use strict;             # keeps us honest
use generator_library;  # includes all the code we'll need???








generator_enable_mode ("terse");





generator_begin (@ARGV);



generator_make_module_wrapper(1, "i2c_master_top");



















generator_copy_files_and_set_system_ptf ("simulation_and_quartus", 
                ("i2c_master_bit_ctrl.v","i2c_master_byte_ctrl.v","i2c_master_defines.v","i2c_master_top.v"));





generator_end ();





exit (0);

