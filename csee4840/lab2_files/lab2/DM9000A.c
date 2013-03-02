#include <stdio.h>
#include "DM9000A.h"
#include "basic_io.h"

void dm9000a_iow(unsigned int reg, unsigned int data)
{
  IOWR(DM9000A_BASE, IO_addr, reg);
  //HiFreqTrade
  //printf("DMA9000A_BASE:%X  IO_addr:%X  reg:%X\n",DM9000A_BASE,IO_addr,reg);
  //printf("     IO_address:%X  register:%X\n",IO_addr,reg);
  usleep(STD_DELAY);
  IOWR(DM9000A_BASE, IO_data, data);
  //HiFreqTrade
  //printf("DMA9000A_BASE:%X  IO_data:%d  reg:%X\n",DM9000A_BASE,IO_data,data);
  // printf("     IO_data:%d  register:%X\n",IO_data,data);
  // printf("-------------------------------\n");
}

unsigned int dm9000a_ior(unsigned int reg)
{
  IOWR(DM9000A_BASE, IO_addr, reg);
  //printf("  IO_address:%X register:%X\n",IO_addr,reg);
  usleep(STD_DELAY);
  return IORD(DM9000A_BASE, IO_data);
}


void phy_write(unsigned int reg, unsigned int value)
{ 
  //HFR
  //printf("--------------beginging phy_write(reg,value)----------------\n");
  /* set PHY register address into EPAR REG. 0CH */
  
  //HFR
  //printf("dm9000a_iow(0x0C, reg | 0x40);    reg:%X\n",reg);
  dm9000a_iow(0x0C, reg | 0x40); /* PHY register address setting,
			    and DM9000_PHY offset = 0x40 */
  
  /* fill PHY WRITE data into EPDR REG. 0EH & REG. 0DH */
  //HFR
  //printf("dm9000a_iow(0x0E, ((value >> 8) & 0xFF));    value:%X\n",value);
  dm9000a_iow(0x0E, ((value >> 8) & 0xFF));   /* PHY data high_byte */
  
  // HFR
   //printf("dm9000a_iow(0x0D, value & 0xFF);    value:%X\n",value);
  dm9000a_iow(0x0D, value & 0xFF);            /* PHY data low_byte */

  /* issue PHY + WRITE command = 0xa into EPCR REG. 0BH */
  //printf("dm9000a_iow(0x0B, 0x8);\n");
  dm9000a_iow(0x0B, 0x8);                     /* clear PHY command first */
  
  //printf("IOWR(DM9000A_BASE, IO_data, 0x0A);    IO_data:%d\n",IO_data);
  IOWR(DM9000A_BASE, IO_data, 0x0A);  /* issue PHY + WRITE command */
  usleep(STD_DELAY);
  
  //printf("IOWR(DM9000A_BASE, IO_data, 0x08);    IO_data:%d\n",IO_data);
  IOWR(DM9000A_BASE, IO_data, 0x08);  /* clear PHY command again */
  usleep(50);  /* wait 1~30 us (>20 us) for PHY + WRITE completion */
  //printf("-------------ending phy_write(reg,value)-------------------\n");
}

/* DM9000_init I/O routine */
unsigned int DM9000_init(unsigned char *mac_address)
{
  unsigned int  i;
    //printf("beginging DM9000_init(*mac_address)\n");
    //HiFreqTrade
    //printf("dm9000a_iow(0x1E, 0x01);\n");
  
  /* set the internal PHY power-on (GPIOs normal settings) */
  dm9000a_iow(0x1E, 0x01);  /* GPCR REG. 1EH = 1 selected
		       GPIO0 "output" port for internal PHY */
               
  //HiFreqTrade
  //printf("dm9000a_iow(0x1F, 0x00);\n");
  
  dm9000a_iow(0x1F, 0x00);  /* GPR  REG. 1FH GEPIO0
		       Bit [0] = 0 to activate internal PHY */
  msleep(5);        /* wait > 2 ms for PHY power-up ready */

  /* software-RESET NIC */
    //HiFreqTradehttps://newcourseworks.columbia.edu/welcome/
  //printf("dm9000a_iow(NCR, 0x03);   NCR:%X\n",NCR);
  dm9000a_iow(NCR, 0x03);   /* NCR REG. 00 RST Bit [0] = 1 reset on,
		       and LBK Bit [2:1] = 01b MAC loopback on */
  usleep(20);       /* wait > 10us for a software-RESET ok */
  
  //HiFreqTrade
  //printf("dm9000a_iow(NCR, 0x00);   NCR:%X\n",NCR);
  dm9000a_iow(NCR, 0x00);   /* normalize */
  
  
  
  //HiFreqTrade
  //printf("dm9000a_iow(NCR, 0x03);   NCR:%X\n",NCR);
  dm9000a_iow(NCR, 0x03);
  usleep(20);
  
  //HiFreqTrade
  //printf("dm9000a_iow(NCR, 0x00);   NCR:%X\n",NCR);
  dm9000a_iow(NCR, 0x00);
  
  /* set GPIO0=1 then GPIO0=0 to turn off and on the internal PHY */
  
    //HiFreqTrade
  //printf("dm9000a_iow(0x1F, 0x01);\n");
  dm9000a_iow(0x1F, 0x01);  /* GPR PHYPD Bit [0] = 1 turn-off PHY */
  
  
  //HiFreqTrade
  //printf("dm9000a_iow(0x1F, 0x00);\n");
  dm9000a_iow(0x1F, 0x00);  /* PHYPD Bit [0] = 0 activate phyxcer */
  msleep(10);       /* wait >4 ms for PHY power-up */
  
    //HiFreqTrade
  //printf("dm9000a_iow(0x1F, 0x00);\n");
  
  /* set PHY operation mode */
  //HFR
  //printf("phy_write(0,PHY_reset);   PHY_reset:%X\n",PHY_reset);
  phy_write(0,PHY_reset);   /* reset PHY registers back to the default state */
  usleep(50);               /* wait >30 us for PHY software-RESET ok */
  
  //printf("phy_write(16, 0x404);\n");
  phy_write(16, 0x404);     /* turn off PHY reduce-power-down mode only */
  
  //HFR
  //printf("phy_write(4, PHY_txab);   PHY_txab:%X\n",PHY_txab);
  phy_write(4, PHY_txab);   /* set PHY TX advertised ability:
			       ALL + Flow_control */
                   
  //printf("phy_write(0, 0x1200);\n");
  phy_write(0, 0x1200);     /* PHY auto-NEGO re-start enable
			       (RESTART_AUTO_NEGOTIATION +
			       AUTO_NEGOTIATION_ENABLE)
			       to auto sense and recovery PHY registers */
  msleep(5);                /* wait >2 ms for PHY auto-sense
			       linking to partner */

  /* store MAC address into NIC */
  for (i = 0; i < 6; i++) 
    //printf("dm9000a_iow(16 + %d, mac_address[%d]); mac_address[i]:%d\n",i,i,mac_address[i]);
    dm9000a_iow(16 + i, mac_address[i]);
  
    //HiFreqTrade
  //printf("dm9000a_iow(ISR, 0x3F); ISR:%X\n",ISR);
  
  
  /* clear any pending interrupt */
  dm9000a_iow(ISR, 0x3F);  /* clear the ISR status: PRS, PTS, ROS, ROOS 4 bits,
		      by RW/C1 */
              
  //HiFreqTrade
  //printf("dm9000a_iow(NSR, 0x2C); NSR:%X\n",NSR);
              
  dm9000a_iow(NSR, 0x2C);  /* clear the TX status: TX1END, TX2END, WAKEUP 3 bits,
		      by RW/C1 */

  //HiFreqTrade
  //printf("dm9000a_iow(NSR, 0x2C); NCR:%X    NCR_set,%X\n",NCR,NCR_set);



  /* program operating registers~ */
  dm9000a_iow(NCR, NCR_set); /* NCR REG. 00 enable the chip functions
			(and disable this MAC loopback mode back to normal) */
            
  //HiFreqTrade
  //printf("dm9000a_iow(0x08, BPTR_set); BPTR_set:%X\n",BPTR_set);
  
  dm9000a_iow(0x08, BPTR_set); /* BPTR  REG.08  (if necessary) RX Back Pressure
			  Threshold in Half duplex moe only:
			  High Water 3KB, 600 us */
              
  //HiFreqTrade
  //printf("dm9000a_iow(0x09, FCTR_set); FCTR_set:%X\n",FCTR_set);             
  dm9000a_iow(0x09, FCTR_set);  /* FCTR  REG.09  (if necessary)
			   Flow Control Threshold setting
			   High/ Low Water Overflow 5KB/ 10KB */
 
   //HiFreqTrade
  //printf("dm9000a_iow(0x0A, RTFCR_set); RTFCR_set:%X\n",RTFCR_set); 
               
  dm9000a_iow(0x0A, RTFCR_set); /* RTFCR REG.0AH (if necessary)
			   RX/TX Flow Control Register enable TXPEN, BKPM
			   (TX_Half), FLCE (RX) */
               
  //HiFreqTrade
  //printf("dm9000a_iow(0x0F, 0x00);\n"); 
  dm9000a_iow(0x0F, 0x00);      /* Clear the all Event */
  
  
    //HiFreqTrade
  //printf("dm9000a_iow(0x2D, 0x80);\n"); 
  dm9000a_iow(0x2D, 0x80);      /* Switch LED to mode 1 */


    //HiFreqTrade
  //printf("dm9000a_iow(ETXCSR, ETXCSR_set);  ETXCSR:%X   ETXCSR_set:%X\n",ETXCSR,ETXCSR_set); 
  /* set other registers depending on applications */
  dm9000a_iow(ETXCSR, ETXCSR_set); /* Early Transmit 75% */
  
  
    //HiFreqTrade
  //printf("dm9000a_iow(IMR, INTR_set);  IMR:%X   INTR_set:%X\n",IMR,INTR_set); 
  /* enable interrupts to activate DM9000 ~on */
  dm9000a_iow(IMR, INTR_set);   /* IMR REG. FFH PAR=1 only,
			   or + PTM=1& PRM=1 enable RxTx interrupts */


    //HiFreqTrade
  //printf("dm9000a_iow(RCR , RCR_set | RX_ENABLE | PASS_MULTICAST);  RCR:%X   RCR_set:%X     RX_ENABLE:%X    PASS_MULTICAST:%X\n",RCR , RCR_set,RX_ENABLE,PASS_MULTICAST); 
 

  /* enable RX (Broadcast/ ALL_MULTICAST) ~go */
  dm9000a_iow(RCR , RCR_set | RX_ENABLE | PASS_MULTICAST);
  /* RCR REG. 05 RXEN Bit [0] = 1 to enable the RX machine/ filter */
   // dm9000a_iow(TCR, TCS_set);
   // dm9000a_iow(RCR, RCS_set);
  /* RETURN "DEVICE_SUCCESS" back to upper layer */
  
  //printf("ending DM9000_init(*mac_address)\n");
  return  (dm9000a_ior(0x2D)==0x80) ? DMFE_SUCCESS : DMFE_FAIL;
}

unsigned int TransmitPacket(unsigned char *data_ptr, unsigned int tx_len)
{
  unsigned int i;
  
  /* mask NIC interrupts IMR: PAR only */
  dm9000a_iow(IMR, PAR_set);
  
  /* issue TX packet's length into TXPLH REG. FDH & TXPLL REG. FCH */
  dm9000a_iow(0xFD, (tx_len >> 8) & 0xFF);  /* TXPLH High_byte length */
  dm9000a_iow(0xFC, tx_len & 0xFF);         /* TXPLL Low_byte  length */

  /* wirte transmit data to chip SRAM */
  IOWR(DM9000A_BASE, IO_addr, MWCMD);  /* set MWCMD REG. F8H
					  TX I/O port ready */
  for (i = 0; i < tx_len; i += 2) {
    usleep(STD_DELAY);
    IOWR(DM9000A_BASE, IO_data, (data_ptr[i+1]<<8)|data_ptr[i] );
  }

  /* issue TX polling command activated */
  dm9000a_iow(TCR , TCR_set | TX_REQUEST);  /* TXCR Bit [0] TXREQ auto clear
				       after TX completed */

  /* wait TX transmit done */
  while(!(dm9000a_ior(NSR)&0x0C))
    usleep(STD_DELAY);

  /* clear the NSR Register */
  dm9000a_iow(NSR,0x00);
  
  /* re-enable NIC interrupts */
  dm9000a_iow(IMR, INTR_set);

  /* RETURN "TX_SUCCESS" to upper layer */
  return  DMFE_SUCCESS;
}

unsigned int ReceivePacket(unsigned char *data_ptr, unsigned int *rx_len)
{
    //printf("------begining function ReceivePacket(data_ptr,rx_len);------\n");
  unsigned char rx_READY, GoodPacket;
  unsigned int  Tmp, RxStatus, i;
  RxStatus = rx_len[0] = 0;
  GoodPacket=FALSE;

  /* mask NIC interrupts IMR: PAR only */
  //printf("dm9000a_iow(IMR, PAR_set);    IMR:%X  PAR_set:%X\n",IMR,PAR_set);
  dm9000a_iow(IMR, PAR_set);
  
  
  //printf("rx_READY = dm9000a_ior(MRCMDX);\n");
  /* dummy read a byte from MRCMDX REG. F0H */
  rx_READY = dm9000a_ior(MRCMDX);
  
  //printf("rx_READY = IORD(DM9000A_BASE,IO_data)&0x03;   IO_data:%d\n",IO_data);
  /* got most updated byte: rx_READY */
  rx_READY = IORD(DM9000A_BASE,IO_data)&0x03;
  usleep(STD_DELAY);
  
  //printf(" check if (rx_READY == 0x01): Received Packet READY? \n");
  /* check if (rx_READY == 0x01): Received Packet READY? */
  if (rx_READY == DM9000_PKT_READY) {

    //printf("IOWR(DM9000A_BASE, IO_addr, MRCMD); IO_addr:%X  MRCMD:%X\n",IO_addr,MRCMD); 
    /* got RX_Status & RX_Length from RX SRAM */
    IOWR(DM9000A_BASE, IO_addr, MRCMD); /* set MRCMD REG. F2H
					   RX I/O port ready */
    usleep(STD_DELAY);
    //printf("RxStatus = IORD(DM9000A_BASE,IO_data);  IO_data:%d\n",IO_data);
    RxStatus = IORD(DM9000A_BASE,IO_data);
    usleep(STD_DELAY);
    
    //printf("rx_len[0] = IORD(DM9000A_BASE,IO_data);  IO_data:%d\n",IO_data);
    rx_len[0] = IORD(DM9000A_BASE,IO_data);

    //printf(" Check this packet_status GOOD or BAD? \n");
    //printf("if ( !(RxStatus & 0xBF00) && (rx_len[0] < MAX_PACKET_SIZE) )\n");
    /* Check this packet_status GOOD or BAD? */
    if ( !(RxStatus & 0xBF00) && (rx_len[0] < MAX_PACKET_SIZE) ) {
      /* read 1 received packet from RX SRAM into RX buffer */
      for (i = 0; i < rx_len[0]; i += 2) {
	usleep(STD_DELAY);
	Tmp = IORD(DM9000A_BASE, IO_data);
	data_ptr[i] = Tmp & 0xFF;
	data_ptr[i+1] = (Tmp>>8) & 0xFF;
      }
      GoodPacket = TRUE;
    } else {
      /* this packet is bad, dump it from RX SRAM */
      for (i = 0; i < rx_len[0]; i += 2) {
	usleep(STD_DELAY);
	Tmp = IORD(DM9000A_BASE, IO_data);        
      }
      printf("\nError\n");
      rx_len[0] = 0;
    }
  } else if (rx_READY) { /* status check first byte:
			    rx_READY Bit[1:0] must be "00"b or "01"b */

    /* software-RESET NIC */

    //printf("dm9000a_iow(NCR, 0x03);   NCR:%X\n",NCR);
    dm9000a_iow(NCR, 0x03);   /* NCR REG. 00 RST Bit [0] = 1 reset on,
			 and LBK Bit [2:1] = 01b MAC loopback on */
    usleep(20);       /* wait > 10us for a software-RESET ok */
    //printf("dm9000a_iow(NCR, 0x00);   NCR:%X\n",NCR);
    dm9000a_iow(NCR, 0x00);   /* normalize */
    
    //printf("dm9000a_iow(NCR, 0x03);   NCR:%X\n",NCR);
    dm9000a_iow(NCR, 0x03);
    usleep(20);
    
    
    //printf("dm9000a_iow(NCR, 0x00);   NCR:%X\n",NCR);
    dm9000a_iow(NCR, 0x00);    
    /* program operating registers~ */
    //printf("dm9000a_iow(NCR, NCR_set);   NCR:%X NCR_set:%X\n",NCR,NCR_set);
    dm9000a_iow(NCR, NCR_set); /* NCR REG. 00 enable the chip functions
			 (and disable this MAC loopback mode back to normal) */
    //printf("dm9000a_iow(0x08, BPTR_set);   BPTR_set:%X\n",BPTR_set);
    dm9000a_iow(0x08, BPTR_set);  /* BPTR  REG.08  (if necessary) RX Back Pressure
			     Threshold in Half duplex moe only:
			     High Water 3KB, 600 us */
                 
    //printf("dm9000a_iow(0x09, FCTR_set);   FCTR_set:%X\n",FCTR_set);
    dm9000a_iow(0x09, FCTR_set);  /* FCTR  REG.09  (if necessary)
			     Flow Control Threshold setting High/Low Water
			     Overflow 5KB/ 10KB */
    //printf("dm9000a_iow(0x0A, RTFCR_set);   RTFCR:%X\n",RTFCR_set);
    dm9000a_iow(0x0A, RTFCR_set); /* RTFCR REG.0AH (if necessary)
			     RX/TX Flow Control Register
			     enable TXPEN, BKPM (TX_Half), FLCE (RX) */
    //printf("dm9000a_iow(0x0F, 0x00);\n");
    dm9000a_iow(0x0F, 0x00);      /* Clear the all Event */
    
    //printf("dm9000a_iow(0x2D, 0x80);\n");
    dm9000a_iow(0x2D, 0x80);      /* Switch LED to mode 1 */
    /* set other registers depending on applications */
    //printf("dm9000a_iow(ETXCSR, ETXCSR_set); ETXCSR:%X  ETXCSR_set:%X\n",ETXCSR,ETXCSR_set);
    dm9000a_iow(ETXCSR, ETXCSR_set); /* Early Transmit 75% */
    /* enable interrupts to activate DM9000 ~on */
    
    //printf("dm9000a_iow(IMR, INTR_set); IMR:%X  INTR_set:%X\n",IMR,INTR_set);
    dm9000a_iow(IMR, INTR_set);   /* IMR REG. FFH PAR=1 only,
			     or + PTM=1& PRM=1 enable RxTx interrupts */
    /* enable RX (Broadcast/ ALL_MULTICAST) ~go */
    //printf("dm9000a_iow(RCR , RCR_set | RX_ENABLE | PASS_MULTICAST); RCR:%X  RCR_Set:%X RX_ENABLE:%X    PASS_MULTICAST:%X\n",RCR,RCR_set,RX_ENABLE,PASS_MULTICAST);
    dm9000a_iow(RCR , RCR_set | RX_ENABLE | PASS_MULTICAST);
      /* RCR REG. 05 RXEN Bit [0] = 1 to enable the RX machine/ filter */
  }
  //printf("---ending function ReceivePacket(data_ptr,rx_len);----------\n");
  return GoodPacket ? DMFE_SUCCESS : DMFE_FAIL;
}
