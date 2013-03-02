-- Copyright (C) 1991-2007 Altera Corporation
-- Your use of Altera Corporation's design tools, logic functions 
-- and other software and tools, and its AMPP partner logic 
-- functions, and any output files from any of the foregoing 
-- (including device programming or simulation files), and any 
-- associated documentation or information are expressly subject 
-- to the terms and conditions of the Altera Program License 
-- Subscription Agreement, Altera MegaCore Function License 
-- Agreement, or other applicable license agreement, including, 
-- without limitation, that your use is for the sole purpose of 
-- programming logic devices manufactured by Altera and sold by 
-- Altera or its authorized distributors.  Please refer to the 
-- applicable agreement for further details.

-- ***************************************************************************
-- This file contains a Vhdl test bench template that is freely editable to   
-- suit user's needs .Comments are provided in each section to help the user  
-- fill out necessary details.                                                
-- ***************************************************************************
-- Generated on "02/07/2012 19:54:24"
                                                            
-- Vhdl Test Bench template for design  :  lab1
-- 
-- Simulation tool : ModelSim-Altera (VHDL)
-- 

LIBRARY ieee;                                               
USE ieee.std_logic_1164.all;                                

ENTITY lab1_vhd_tst IS
END lab1_vhd_tst;
ARCHITECTURE lab1_arch OF lab1_vhd_tst IS
-- constants                                                 
-- signals                                                   
SIGNAL clock : STD_LOGIC :='0';
SIGNAL hex4 : STD_LOGIC_VECTOR(6 DOWNTO 0);
SIGNAL hex5 : STD_LOGIC_VECTOR(6 DOWNTO 0);
SIGNAL hex6 : STD_LOGIC_VECTOR(6 DOWNTO 0);
SIGNAL key : STD_LOGIC_VECTOR(3 DOWNTO 0);

COMPONENT lab1
	PORT (
	clock : IN STD_LOGIC;
	hex4 : OUT STD_LOGIC_VECTOR(6 DOWNTO 0);
	hex5 : OUT STD_LOGIC_VECTOR(6 DOWNTO 0);
	hex6 : OUT STD_LOGIC_VECTOR(6 DOWNTO 0);
	key : IN STD_LOGIC_VECTOR(3 DOWNTO 0)
	);
END COMPONENT;

BEGIN
clock <= not clock after 20 ns;	




--init1 : PROCESS 
--begin
--clock <= '0';
--wait for 20 ns;
--loop
--clock <= '1';
--wait for 20 ns;
--clock <= '1';
--wait for 20 ns;
--end loop;
--END PROCESS init1; 



	--i1 : lab1
	i1: lab1
	PORT MAP (
-- list connections between master ports and signals
	clock => clock,
	hex4 => hex4,
	hex5 => hex5,
	hex6 => hex6,
	key => key
	);
init : PROCESS                                               
-- variable declarations                                     
BEGIN                                                        


	key <= "1101";   -- code that executes only once
	wait for 50ms;  
	key <= "1011"; 
	wait for 50ms;  
WAIT;                                                       
END PROCESS init;                                           
always : PROCESS                                              
-- optional sensitivity list                                  
-- (        )                                                 
-- variable declarations                                      
BEGIN                                                         
        -- code executes for every event on sensitivity list  
WAIT;                                                        
END PROCESS always;                                          
END lab1_arch;
