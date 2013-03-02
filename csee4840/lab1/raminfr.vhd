library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;


entity raminfr is
port (
clock : in std_logic;
we : in std_logic;
a : in unsigned(3 downto 0);
di : in unsigned(7 downto 0);
do : out unsigned(7 downto 0)
);
end raminfr;

architecture rtl of raminfr is
type ram_type is array (0 to 15) of unsigned(7 downto 0); 
signal RAM:ram_type:=(others=>(others=>'0'));
signal read_a:unsigned(3 downto 0);
begin


process (clock)
begin
if rising_edge(clock) then
	if we = '1' then
		RAM(to_integer(a)) <= di;
	end if ;
	read_a <= a;
end if ;
end process;

do <= RAM(to_integer(read_a));

end rtl;

