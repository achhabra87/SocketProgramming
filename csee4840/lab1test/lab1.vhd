library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;


entity lab1 is

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
end lab1;


architecture RTL1 of lab1 is
	
signal do:unsigned(7 downto 0);
signal a:unsigned(3 downto 0);
signal di:unsigned(7 downto 0);
signal we:std_logic;
component ctrl is
port(
		key	: in  std_logic_vector(3 downto 0);
		clock : in std_logic;
		do:in unsigned(7 downto 0);
		
		-- Output ports
		di : out unsigned(7 downto 0);
		a : out unsigned(3 downto 0);
		we : out std_logic 
);
end component ctrl;

component raminfr is
port (
	clk : in std_logic;
	we : in std_logic;
	a : in unsigned(3 downto 0);
	di : in unsigned(7 downto 0);
	do : out unsigned(7 downto 0)
);
end component raminfr;

component hexdecoder is
port(
		inputdata: in  unsigned(3 downto 0);
		-- Output ports
		output: out std_logic_vector(6 downto 0)
);
end component hexdecoder;
	-- Declarations (optional)
begin
ctrlUnit:ctrl port map(key=>key,clock=>clock,do=>do,di=>di,a=>a,we=>we);
raminfrUnit:raminfr port map(clk=>clock,we=>we,a=>a,di=>di,do=>do);


hexdec4:hexdecoder port map(a,hex6);
hexdec5:hexdecoder port map(do(7 downto 4),hex5);
hexdec6:hexdecoder port map(do(3 downto 0),hex4);


	-- Concurrent Procedure Call (optional)

	-- Concurrent Signal Assignment (optional)

	-- Conditional Signal Assignment (optional)

	-- Selected Signal Assignment (optional)

	-- Component Instantiation Statement (optional)

	-- Generate Statement (optional)

end RTL1;
