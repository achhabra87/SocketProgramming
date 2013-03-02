library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity DE2_TOP_test is --  no ports
end DE2_TOP_test ;

architecture tb of DE2_TOP_test is

signal key:std_logic_vector(3 downto 0); -- case when key is not pressed
signal	clock:std_logic:='0';	

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

i1 : lab1 port map(key => key,clock => clock,hex6=> hex6,hex5 => hex5,hex4 => hex4); 
clock <= not clock after 20 ns; -- 50 MHz
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
key <= "1111"; -- increment data at address X by 1
wait for 10ms;
key <= "0111"; -- increment data at address X by 1
wait for 10ms;
key <= "1111"; -- increment data at address X by 1
wait for 1ms;
key <= "1011"; 
wait for 10ms;
key <= "1111"; -- increment data at address X by 1
wait for 1ms;
key <= "1101"; 
wait for 10ms;
key <= "1111"; -- increment data at address X by 1
wait for 1ms;
key <= "1110"; 
wait for 10ms;
key <= "1111"; -- increment data at address X by 1
wait for 1ms;
key <= "1110"; 
wait for 10ms;

wait;
end process;

	
end tb;