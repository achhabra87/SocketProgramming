library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;


entity ctrl is

	port
	(
		-- Input ports
		key	: in  std_logic_vector(3 downto 0);
		clock : in std_logic;
		do:in unsigned(7 downto 0);
		
		-- Output ports
		di : out unsigned(7 downto 0);
		a : out unsigned(3 downto 0);
		we : out std_logic 
	);
end ctrl;

architecture ctrlArch of ctrl is
signal address:unsigned(3 downto 0):=(others=>'0');
signal datain:unsigned (7 downto 0):=(others=>'0');
signal writeEnable:std_logic:='0';

begin

process(clock)
variable countClock:integer range 0 to 500000;
variable button:std_logic;
begin
if (rising_edge(clock))then      
	if(key/="1111")then			 
		if(countClock>=500000)then   
			if(key="0111")then		
				address<=address+"0001";-- Increase address by 1
			elsif key="1011" then 	--Decrease address by 1
				address<=address-"0001";
			elsif(key="1110")then
				writeEnable<='1';
				datain<=do-1;
			elsif(key="1101")then
				writeEnable<='1';
				datain<=do+1;
			end if;					
		countClock:=0;
		button:='0';

--	
	else 
		if(button='1')then
				countClock:=countClock+1;
		end if;
	end if;

	else
		button:='1';
		countClock:=0;
		writeEnable<='0';
	end if;
end if;

end process;
a<=address;
we<=writeEnable;
di<=datain;

end ctrlArch;