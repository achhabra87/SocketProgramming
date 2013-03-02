library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;


entity hexdecoder is
	port
	(
		-- Input ports
		inputdata : in  unsigned(3 downto 0);



		-- Output ports
		output: out std_logic_vector(6 downto 0)

	);
end hexdecoder;


architecture RTL2 of hexdecoder is

	-- Declarations (optional)

begin
with inputdata select output <=

"1000000" when x"0", 
"1111001" when x"1",
"0100100" when x"2", 
"0110000" when x"3",
"0011001" when x"4", 
"0010010" when x"5",
"0000010" when x"6", 
"1111000" when x"7",
"0000000" when x"8", 
"0011000" when x"9",
"0001000" when x"A", 
"0000011" when x"B",
"1000110" when x"C", 
"0100001" when x"D",
"0000110" when x"E", 
"0001110" when x"F",
"1111111" when others;



	-- Process Statement (optional)

	-- Concurrent Procedure Call (optional)

	-- Concurrent Signal Assignment (optional)

	-- Conditional Signal Assignment (optional)

	-- Selected Signal Assignment (optional)

	-- Component Instantiation Statement (optional)

	-- Generate Statement (optional)

end RTL2;