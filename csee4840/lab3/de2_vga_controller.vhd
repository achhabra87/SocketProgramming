library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity de2_vga_controller is

 port (
   clk        : in  std_logic;
   reset_n    : in  std_logic;

   write      : in  std_logic;
   chipselect : in  std_logic;


   writedata  : in  unsigned(31 downto 0);

   center_x : out unsigned(9 downto 0);
   center_y : out unsigned(9 downto 0)

   );

end de2_vga_controller;

architecture rtl of de2_vga_controller is

begin

 process (clk)
 begin
   if rising_edge(clk) then
     if reset_n = '0' then
       center_x <= "0000000000";
       center_y <= "0000000000";
     else
       if chipselect = '1' then
           if write = '1' then
               center_x <= writedata(19 downto 10);
               center_y <= writedata(9 downto 0);
           end if;
       end if;
     end if;
   end if;

 end process;

end rtl;