// --------------------------------------------------------------------
// Copyright (c) 2005 by Terasic Technologies Inc. 
// --------------------------------------------------------------------
//
// Permission:
//
//   Terasic grants permission to use and modify this code for use
//   in synthesis for all Terasic Development Boards and Altera Development 
//   Kits made by Terasic.  Other use of this code, including the selling 
//   ,duplication, or modification of any portion is strictly prohibited.
//
// Disclaimer:
//
//   This VHDL/Verilog or C/C++ source code is intended as a design reference
//   which illustrates how these types of functions can be implemented.
//   It is the user's responsibility to verify their design for
//   consistency and functionality through the use of formal
//   verification methods.  Terasic provides no warranty regarding the use 
//   or functionality of this code.
//
// --------------------------------------------------------------------
//           
//                     Terasic Technologies Inc
//                     356 Fu-Shin E. Rd Sec. 1. JhuBei City,
//                     HsinChu County, Taiwan
//                     302
//
//                     web: http://www.terasic.com/
//                     email: support@terasic.com
//
// --------------------------------------------------------------------
//
// Major Functions:	DE2 Ethernet Reference Design
//
// --------------------------------------------------------------------
//
// Revision History :
// --------------------------------------------------------------------
//   Ver  :| Author            :| Mod. Date :| Changes Made:
//   V1.0 :| Johnny Chen       :| 05/08/19  :| Initial Revision
//   V1.1 :| Johnny Chen       :| 05/11/16  :| Add to FLASH Address FL_ADDR[21:20]
// --------------------------------------------------------------------
module DE2_NET
	(
		//	Onboard Oscilator	 
		OSC_27,
		OSC_50,
		//	Push Button
		KEY,
		//	DPDT Switch
		DPDT_SW,
		//	7-SEG Dispaly
		HEX0,
		HEX1,
		HEX2,
		HEX3,
		HEX4,
		HEX5,
		HEX6,
		HEX7,
		//	LED
		LED_GREEN,
		LED_RED,
		//	UART
		UART_TXD,
		UART_RXD,
		//	SDRAM Interface
		DRAM_DQ,	//	16 Bits
		DRAM_ADDR,	//	12 Bits
		DRAM_LDQM,
		DRAM_UDQM,
		DRAM_WE_N,
		DRAM_CAS_N,
		DRAM_RAS_N,
		DRAM_CS_N,
		DRAM_BA_0,
		DRAM_BA_1,
		DRAM_CLK,
		DRAM_CKE,	
		//	Flash Interface
		FL_DQ,		//	8 Bits
		FL_ADDR,	//	22 Bits
		FL_WE_N,
		FL_RST_N,
		FL_OE_N,
		FL_CE_N,
		//	SRAM Interface
		SRAM_DQ,	//	16 Bits
		SRAM_ADDR,	//	18 Bits
		SRAM_UB_N,
		SRAM_LB_N,
		SRAM_WE_N,
		SRAM_CE_N,
		SRAM_OE_N,
		//	ISP1362 Interface
		OTG_DATA,	//	16 Bits
		OTG_ADDR,	//	2 Bits
		OTG_CS_N,
		OTG_RD_N,
		OTG_WR_N,
		OTG_RST_N,
		OTG_FSPEED,	//	USB Full Speed,	0 = Enable, Z = Disable
		OTG_LSPEED,	//	USB Low Speed, 	0 = Enable, Z = Disable
		OTG_INT0,
		OTG_INT1,
		OTG_DREQ0,
		OTG_DREQ1,
		OTG_DACK0_N,
		OTG_DACK1_N,
		//	Ethernet Interface
		ENET_DATA,
		ENET_CMD,
		ENET_CS_N,
		ENET_WR_N,
		ENET_RD_N,
		ENET_RST_N,
		ENET_INT,
		ENET_CLK,
		//	LCD Module 16X2
		LCD_ON,		//	LCD ON/OFF
		LCD_BLON,	//	LCD Back Light ON/OFF
		LCD_RW,
		LCD_EN,
		LCD_RS,
		LCD_DATA,
		//	SD_Card Interface
		SD_CMD,
		SD_CLK,
		SD_DATA,
		//	I2C
		I2C_DATA,
		I2C_CLK,
		//	PS2
		PS2_DATA,
		PS2_CLK,
                // VGA
		VGA_CLK,   						//	VGA Clock
		VGA_HS,							//	VGA H_SYNC
		VGA_VS,							//	VGA V_SYNC
		VGA_BLANK,						//	VGA BLANK
		VGA_SYNC,						//	VGA SYNC
		VGA_R,   						//	VGA Red[9:0]
		VGA_G,	 						//	VGA Green[9:0]
		VGA_B,  						//	VGA Blue[9:0]

		
		TD_RESET
	);

//	On Board Oscilator
input			OSC_27;
input			OSC_50;
//	Push Button
input	[3:0]	KEY;
//	DPDT Switch
input	[17:0]	DPDT_SW;
//	7-SEG Dispaly
output	[6:0]	HEX0;
output	[6:0]	HEX1;
output	[6:0]	HEX2;
output	[6:0]	HEX3;
output	[6:0]	HEX4;
output	[6:0]	HEX5;
output	[6:0]	HEX6;
output	[6:0]	HEX7;
//	LED
output	[8:0]	LED_GREEN;
output	[17:0]	LED_RED;
//	UART
output			UART_TXD;
input			UART_RXD;
//	SDRAM Interface
inout	[15:0]	DRAM_DQ;	// 16 Bits
output	[11:0]	DRAM_ADDR;	// 12 Bits
output			DRAM_LDQM;
output			DRAM_UDQM;
output			DRAM_WE_N;
output			DRAM_CAS_N;
output			DRAM_RAS_N;
output			DRAM_CS_N;
output			DRAM_BA_0;
output			DRAM_BA_1;
output			DRAM_CLK;
output			DRAM_CKE;
//	Flash Interface
inout	[7:0]	FL_DQ;		//	8 Bits
output	[21:0]	FL_ADDR;	//	22 Bits
output			FL_WE_N;
output			FL_RST_N;
output			FL_OE_N;
output			FL_CE_N;
//	SRAM Interface
inout	[15:0]	SRAM_DQ;	//	16 Bits
output	[17:0]	SRAM_ADDR;	//	18 Bits
output			SRAM_UB_N;
output			SRAM_LB_N;
output			SRAM_WE_N;
output			SRAM_CE_N;
output			SRAM_OE_N;
//	ISP1362 Interface
inout	[15:0]	OTG_DATA;
output	[1:0]	OTG_ADDR;
output			OTG_WR_N;
output			OTG_RD_N;
output			OTG_CS_N;
output			OTG_RST_N;
output			OTG_FSPEED;		//	USB Full Speed,	0 = Enable, Z = Disable
output			OTG_LSPEED;		//	USB Low Speed, 	0 = Enable, Z = Disable
input			OTG_INT0;
input			OTG_INT1;
input			OTG_DREQ0;
input			OTG_DREQ1;
output			OTG_DACK0_N;
output			OTG_DACK1_N;
//	Ethernet Interface
inout	[15:0]	ENET_DATA;
output			ENET_CMD;
output			ENET_CS_N;
output			ENET_WR_N;
output			ENET_RD_N;
output			ENET_RST_N;
input			ENET_INT;
output			ENET_CLK;
//	LCD Module 16X2
inout	[7:0]	LCD_DATA;
output			LCD_ON;		//	LCD ON/OFF
output			LCD_BLON;	//	LCD Back Light ON/OFF
output			LCD_RW;
output			LCD_EN;
output			LCD_RS;
//	SD_Card Interface
inout			SD_DATA;
output			SD_CLK;
output			SD_CMD;
//	I2C
inout			I2C_DATA;
inout			I2C_CLK;
//	PS2
inout		 	PS2_DATA;
inout			PS2_CLK;
////////////////////////	VGA			////////////////////////////
output			VGA_CLK;   				//	VGA Clock
output			VGA_HS;					//	VGA H_SYNC
output			VGA_VS;					//	VGA V_SYNC
output			VGA_BLANK;				//	VGA BLANK
output			VGA_SYNC;				//	VGA SYNC
output	[9:0]	VGA_R;   				//	VGA Red[9:0]
output	[9:0]	VGA_G;	 				//	VGA Green[9:0]
output	[9:0]	VGA_B;   				//	VGA Blue[9:0]


output			TD_RESET;

assign			TD_RESET	=	1'b1;

//////////////////////////////////////////////////////////
wire	[31:0]	mSEG7_HEX;
wire	[15:0]	DATA_to_OTG;
wire	[15:0]	DATA_to_SRAM;
//	I2C
wire			SCL_OE_N;
wire			SDA_OE_N;
wire			SCL;
wire			SDA;
//	CPU
wire			CPU_RESET;

reg				ENET_CLK;
always@(posedge OSC_50)	ENET_CLK=~ENET_CLK;

//	16*2 LCD Module
assign	LCD_ON		=	1'b1;	//	LCD ON
assign	LCD_BLON	=	1'b1;	//	LCD Back Light	
assign	FL_RST_N	=	1'b1;
assign	FL_ADDR[21:20]	=	2'b00;	//	Fixed 1M-Byte FLASH

//	I2C Tri-inout
assign	I2C_CLK		=	SCL_OE_N	?	1'bz	:	SCL	;
assign	I2C_DATA	=	SDA_OE_N	?	1'bz	:	SDA	;

SDRAM_PLL 	PLL1	(.inclk0(OSC_50),.c0(DRAM_CLK));

Reset_Delay	rst		(OSC_50,CPU_RESET);

nios_0		u0	(
                // 1) global signals:
                 .clk(OSC_50),
                 .reset_n(CPU_RESET),

                // the_lcd_16207_0
                 .LCD_E_from_the_lcd_16207_0(LCD_EN),
                 .LCD_RS_from_the_lcd_16207_0(LCD_RS),
                 .LCD_RW_from_the_lcd_16207_0(LCD_RW),
                 .LCD_data_to_and_from_the_lcd_16207_0(LCD_DATA),

                // the_SEG7_Display
                 .oSEG0_from_the_SEG7_Display(HEX0),
                 .oSEG1_from_the_SEG7_Display(HEX1),
                 .oSEG2_from_the_SEG7_Display(HEX2),
                 .oSEG3_from_the_SEG7_Display(HEX3),
                 .oSEG4_from_the_SEG7_Display(HEX4),
                 .oSEG5_from_the_SEG7_Display(HEX5),
                 .oSEG6_from_the_SEG7_Display(HEX6),
                 .oSEG7_from_the_SEG7_Display(HEX7),

                // the_ISP1362
                 .OTG_ADDR_from_the_ISP1362(OTG_ADDR),
                 .OTG_CS_N_from_the_ISP1362(OTG_CS_N),
                 .OTG_DACK0_N_from_the_ISP1362(OTG_DACK0_N),
                 .OTG_DACK1_N_from_the_ISP1362(OTG_DACK1_N),
                 .OTG_DATA_to_and_from_the_ISP1362(OTG_DATA),
                 .OTG_DREQ0_to_the_ISP1362(OTG_DREQ0),
                 .OTG_DREQ1_to_the_ISP1362(OTG_DREQ1),
                 .OTG_INT0_to_the_ISP1362(OTG_INT0),
                 .OTG_INT1_to_the_ISP1362(OTG_INT1),
                 .OTG_RD_N_from_the_ISP1362(OTG_RD_N),
                 .OTG_RST_N_from_the_ISP1362(OTG_RST_N),
                 .OTG_WR_N_from_the_ISP1362(OTG_WR_N),
                 .OTG_FSPEED_from_the_ISP1362(OTG_FSPEED),
                 .OTG_LSPEED_from_the_ISP1362(OTG_LSPEED),
                 .iFSPEED_to_the_ISP1362(1'bz),
                 .iLSPEED_to_the_ISP1362(1'bz),

                // the_DM9000A
                 .ENET_CMD_from_the_DM9000A(ENET_CMD),
                 .ENET_CS_N_from_the_DM9000A(ENET_CS_N),
                 .ENET_DATA_to_and_from_the_DM9000A(ENET_DATA),
                 .ENET_INT_to_the_DM9000A(ENET_INT),
                 .ENET_RD_N_from_the_DM9000A(ENET_RD_N),
                 .ENET_RST_N_from_the_DM9000A(ENET_RST_N),
                 .ENET_WR_N_from_the_DM9000A(ENET_WR_N),

                // the_led_green
                 .out_port_from_the_led_green(LED_GREEN),

                // the_led_red
                 .out_port_from_the_led_red(LED_RED),

                // the_switch_pio
                 .in_port_to_the_switch_pio(DPDT_SW),

                // the_button_pio
                 .in_port_to_the_button_pio(KEY),

                // the_sdram_0
                 .zs_addr_from_the_sdram_0(DRAM_ADDR),
                 .zs_ba_from_the_sdram_0({DRAM_BA_1,DRAM_BA_0}),
                 .zs_cas_n_from_the_sdram_0(DRAM_CAS_N),
                 .zs_cke_from_the_sdram_0(DRAM_CKE),
                 .zs_cs_n_from_the_sdram_0(DRAM_CS_N),
                 .zs_dq_to_and_from_the_sdram_0(DRAM_DQ),
                 .zs_dqm_from_the_sdram_0({DRAM_UDQM,DRAM_LDQM}),
                 .zs_ras_n_from_the_sdram_0(DRAM_RAS_N),
                 .zs_we_n_from_the_sdram_0(DRAM_WE_N),

                // the_sram_0
                 .SRAM_ADDR_from_the_sram_0(SRAM_ADDR),
                 .SRAM_CE_N_from_the_sram_0(SRAM_CE_N),
                 .SRAM_DQ_to_and_from_the_sram_0(SRAM_DQ),
                 .SRAM_LB_N_from_the_sram_0(SRAM_LB_N),
                 .SRAM_OE_N_from_the_sram_0(SRAM_OE_N),
                 .SRAM_UB_N_from_the_sram_0(SRAM_UB_N),
                 .SRAM_WE_N_from_the_sram_0(SRAM_WE_N),

                // the_tri_state_bridge_0_avalon_slave
                 .select_n_to_the_cfi_flash_0(FL_CE_N),
                 .tri_state_bridge_0_address(FL_ADDR),
                 .tri_state_bridge_0_data(FL_DQ),
                 .tri_state_bridge_0_readn(FL_OE_N),
                 .write_n_to_the_cfi_flash_0(FL_WE_N),

                // the_I2C_0
                 .scl_pad_i_to_the_I2C_0(I2C_CLK),
                 .scl_pad_o_from_the_I2C_0(SCL),
                 .scl_padoen_o_from_the_I2C_0(SCL_OE_N),
                 .sda_pad_i_to_the_I2C_0(I2C_DATA),
                 .sda_pad_o_from_the_I2C_0(SDA),
                 .sda_padoen_o_from_the_I2C_0(SDA_OE_N),

                // the_uart_0
                 .rxd_to_the_uart_0(UART_RXD),
                 .txd_from_the_uart_0(UART_TXD),

                // the_ps2_0
                 .PS2_CLK_to_and_from_the_ps2_0(PS2_CLK),
		 .PS2_DAT_to_and_from_the_ps2_0(PS2_DATA),

                // the_binary_vga_controller_0
                 .VGA_BLANK_from_the_binary_vga_controller_0(VGA_BLANK),
                 .VGA_B_from_the_binary_vga_controller_0(VGA_B),
                 .VGA_CLK_from_the_binary_vga_controller_0(VGA_CLK),
                 .VGA_G_from_the_binary_vga_controller_0(VGA_G),
                 .VGA_HS_from_the_binary_vga_controller_0(VGA_HS),
                 .VGA_R_from_the_binary_vga_controller_0(VGA_R),
                 .VGA_SYNC_from_the_binary_vga_controller_0(VGA_SYNC),
                 .VGA_VS_from_the_binary_vga_controller_0(VGA_VS),
                 .iCLK_25_to_the_binary_vga_controller_0(ENET_CLK)


              );
endmodule		
