#!/bin/sh
#
# generated.sh - shell script fragment - not very useful on its own
#
# Machine generated for a CPU named "cpu" as defined in:
# /home/user2/spring12/asc2171/csee4840/lab3/software/hello_world_0_syslib/../../nios_system.ptf
#
# Generated: 2012-03-01 18:32:10.092

# DO NOT MODIFY THIS FILE
#
#   Changing this file will have subtle consequences
#   which will almost certainly lead to a nonfunctioning
#   system. If you do modify this file, be aware that your
#   changes will be overwritten and lost when this file
#   is generated again.
#
# DO NOT MODIFY THIS FILE

# This variable indicates where the PTF file for this design is located
ptf=/home/user2/spring12/asc2171/csee4840/lab3/software/hello_world_0_syslib/../../nios_system.ptf

# This variable indicates whether there is a CPU debug core
nios2_debug_core=yes

# This variable indicates how to connect to the CPU debug core
nios2_instance=0

# This variable indicates the CPU module name
nios2_cpu_name=cpu

# Include operating system specific parameters, if they are supplied.

if test -f /opt/altera/altera7.2/nios2eds/components/altera_hal/build/os.sh ; then
   . /opt/altera/altera7.2/nios2eds/components/altera_hal/build/os.sh
fi
