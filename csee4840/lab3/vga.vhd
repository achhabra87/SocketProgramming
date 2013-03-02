--Legal Notice: (C)2007 Altera Corporation. All rights reserved.  Your
--use of Altera Corporation's design tools, logic functions and other
--software and tools, and its AMPP partner logic functions, and any
--output files any of the foregoing (including device programming or
--simulation files), and any associated documentation or information are
--expressly subject to the terms and conditions of the Altera Program
--License Subscription Agreement or other applicable license agreement,
--including, without limitation, that your use is for the sole purpose
--of programming logic devices manufactured by Altera and sold by Altera
--or its authorized distributors.  Please refer to the applicable
--agreement for further details.


-- turn off superfluous VHDL processor warnings 
-- altera message_level Level1 
-- altera message_off 10034 10035 10036 10037 10230 10240 10030 

library altera;
use altera.altera_europa_support_lib.all;

library ieee;
use ieee.std_logic_1164.all;
use ieee.std_logic_arith.all;
use ieee.std_logic_unsigned.all;

entity vga is 
        port (
              -- inputs:
                 signal chipselect : IN STD_LOGIC;
                 signal clk : IN STD_LOGIC;
                 signal reset_n : IN STD_LOGIC;
                 signal write : IN STD_LOGIC;
                 signal writedata : IN STD_LOGIC_VECTOR (31 DOWNTO 0);

              -- outputs:
                 signal center_x : OUT STD_LOGIC_VECTOR (9 DOWNTO 0);
                 signal center_y : OUT STD_LOGIC_VECTOR (9 DOWNTO 0)
              );
end entity vga;


architecture europa of vga is
component de2_vga_controller is 
           port (
                 -- inputs:
                    signal chipselect : IN STD_LOGIC;
                    signal clk : IN STD_LOGIC;
                    signal reset_n : IN STD_LOGIC;
                    signal write : IN STD_LOGIC;
                    signal writedata : IN STD_LOGIC_VECTOR (31 DOWNTO 0);

                 -- outputs:
                    signal center_x : OUT STD_LOGIC_VECTOR (9 DOWNTO 0);
                    signal center_y : OUT STD_LOGIC_VECTOR (9 DOWNTO 0)
                 );
end component de2_vga_controller;

                signal internal_center_x :  STD_LOGIC_VECTOR (9 DOWNTO 0);
                signal internal_center_y :  STD_LOGIC_VECTOR (9 DOWNTO 0);

begin

  --the_de2_vga_controller, which is an e_instance
  the_de2_vga_controller : de2_vga_controller
    port map(
      center_x => internal_center_x,
      center_y => internal_center_y,
      chipselect => chipselect,
      clk => clk,
      reset_n => reset_n,
      write => write,
      writedata => writedata
    );


  --vhdl renameroo for output signals
  center_x <= internal_center_x;
  --vhdl renameroo for output signals
  center_y <= internal_center_y;

end europa;

