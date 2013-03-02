library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity lab1_test is --  no ports
end lab1_test ;

architecture tb of lab1_test is

signal key:std_logic_vector(3 downto 0):="1111"; -- case when key is not pressed
signal	clock:std_logic:='1';	

signal	hex6:std_logic_vector(6 downto 0);
signal	hex5:std_logic_vector(6 downto 0);
signal	hex4:std_logic_vector(6 downto 0); 


component lab1 is
	port
	(
		-- Input ports
		key	: in  std_logic_vector(3 downto 0);
		clock : in std_logic;


		-- Output ports
		hex6 : out std_logic_vector(6 downto 0);
		hex5 : out std_logic_vector(6 downto 0);
		hex4 : out std_logic_vector(6 downto 0) 
	);
end component;


begin
clock <= not clock after 20 ns; -- 50 MHz
dut : lab1 port map(clock => clock,
	hex4 => hex4,
	hex5 => hex5,
	hex6 => hex6,
	key => key); 

--process
--begin
--clock <= '0';
--wait for 20 ns;
--loop
--clock <= '1';
--wait for 20 ns;
--clock <= '1';
--wait for 20 ns;
--end loop;
--end process;


process -- tests
begin
wait for 200ns;
key <= "1101"; -- increment data at address X by 1
--wait for 20us;


wait;
end process;

	
end tb;
