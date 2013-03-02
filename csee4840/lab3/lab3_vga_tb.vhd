--
-- Testbench for the simple VGA raster generator
--
-- Stephen A. Edwards, Columbia University, sedwards@cs.columbia.edu

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity lab3_vga_tb is
  
end lab3_vga_tb;

architecture tb of lab3_vga_tb is

  signal clk, reset : std_logic;
  signal VGA_CLK, VGA_HS, VGA_VS, VGA_BLANK, VGA_SYNC : std_logic;
  signal VGA_R, VGA_G, VGA_B : unsigned(9 downto 0);

begin

  process
  begin
    loop
       clk <= '1';
       wait for 0.5 ns;
       clk <= '0';
       wait for 0.5 ns;
    end loop;
  end process;

  process
  begin
    reset <= '1';
    wait for 5 ns;
    reset <= '0';
    wait;
  end process;

  dut : entity work.de2_vga_raster port map (
    clk => clk,
    reset => reset,
    VGA_CLK => VGA_CLK,
    VGA_HS => VGA_HS,
    VGA_VS => VGA_VS,
    VGA_BLANK => VGA_BLANK,
    VGA_SYNC => VGA_SYNC,
    VGA_R => VGA_R,
    VGA_G => VGA_G,
    VGA_B => VGA_B
  );

end tb;
