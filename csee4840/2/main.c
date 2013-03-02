/*
 * CSEE 4840 Lab 2: Ethernet packet send and receive
 *
 * Stephen A. Edwards et al.
 *
 */

#include "basic_io.h"
#include "DM9000A.h"
#include <alt_types.h>
#include "alt_up_ps2_port.h"
#include "ps2_keyboard.h"
#include "ps2_mouse.h"
#include "LCD.h"
#include "VGA.h"
#include <ctype.h>

#include "lab2_input.h"
#include "lab2_output.h"

#define MAX_MSG_LENGTH 240

// Ethernet MAC address.  Choose the last three bytes yourself
unsigned char mac_address[6] = { 0x01, 0x60, 0x6E, 0x12, 0x03, 0x10  };

unsigned int interrupt_number;

unsigned int receive_buffer_length;
unsigned char receive_buffer[1600] = {0}; /* Be careful about this harcoded value*/

KB_CODE_TYPE decode_mode;

#define UDP_PACKET_PAYLOAD_NAME_LENGTH 5
#define UDP_PACKET_PAYLOAD_OFFSET (42)
#define UDP_PACKET_LENGTH_OFFSET 38

#define IP_PACKET_ID_OFFSET  (18) 

#define IP_HEADER_OFFSET  (14)
#define IP_HEADER_SIZE  (20)
#define IP_HEADER_CHECKSUM_OFFSET  (24)

#define UDP_PACKET_PAYLOAD (transmit_buffer + UDP_PACKET_PAYLOAD_OFFSET + UDP_PACKET_PAYLOAD_NAME_LENGTH )

static int gShiftPressflag = 0;
static int gNameFlag = 1;

static unsigned short int gIPPacketIDNum = 0;

unsigned char transmit_buffer[] = {
  // Ethernet MAC header
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination MAC address
  0x01, 0x60, 0x6E, 0x12, 0x03, 0x10, // Source MAC address
  0x08, 0x00,                         // Packet Type: 0x800 = IP
                          
  // IP Header
  0x45,                // version (IPv4), header length = 20 bytes
  0x00,                // differentiated services field
  0x01,0x9C,           // total length: 20 bytes for IP header +
                       // 8 bytes for UDP header + 240 bytes for payload
  0x3d, 0x35,          // packet ID
  0x00,                // flags
  0x00,                // fragment offset
  0x80,                // time-to-live
  0x11,                // protocol: 11 = UDP
  0x00,0x00,           // header checksum: incorrect
  0xc0,0xa8,0x01,0x01, // source IP address
  0xc0,0xa8,0x01,0xff, // destination IP address
                          
  // UDP Header
  0x67,0xd9, // source port port (26585: garbage)
  0x27,0x2b, // destination port (10027: garbage)
  0x00,0xF8, // length (248: 8 for UDP header + 240 for data)
  0x00,0x00, // checksum: 0 = none
                          
  // UDP payload (240 bytes) (First 5 bytes are for name)
  0x20, 0x20, 0x20, 0x20, 0x3A, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67,
  0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x73, 0x67
};   



unsigned short int IPCheckSum(unsigned char* ipHeader, int iLength)
{
    long sum = 0;  /* Sum is 4 bytes */
    int count = 0;
    unsigned short tempSum = 0;
    /* */
    while(iLength > 1){
        tempSum = *(ipHeader);
        /* Copy the ipHeader lower byte to higher byte of tempSum */
        tempSum = (tempSum << 8) + 0x00; 
        tempSum = tempSum + (*(ipHeader+1));
        sum = sum +  tempSum; /* 2 bytes of ipHeader used */
        ipHeader += 2; /* Move 2 bytes */
        if(sum & 0x80000000){   /* if high order bit set (when 4 bytes of sum may not be enuf)*/
               sum = (sum & 0xFFFF) + (sum >> 16);
        }
        iLength -= 2;
        count++;
    }
        printf("ccount%d\n", count);
    if(iLength){       /* if  ipHeader has odd bytes */
        sum = sum + (unsigned short)(*(ipHeader));
    }
    
    while(sum>>16){ /* Add the contents in 3rd and 4th byte to first 2 bytes */
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return(~sum); /* take 1's compliment and return */
}


static void ethernet_interrupt_handler() {
  unsigned int receive_status;
  int i;
  char *p;
   unsigned short usIPCheckSum = 0;
  
  receive_status = ReceivePacket(receive_buffer, &receive_buffer_length);

  if (receive_status == DMFE_SUCCESS) {

#if 1
    printf("\n\nReceive Packet Length = %d", receive_buffer_length);
    for(i=0;i<receive_buffer_length;i++) {
      if (i%8==0) printf("\n");
      printf("0x%.2X,", receive_buffer[i]);
    }
    printf("\n");
#endif

    if (receive_buffer_length >= 14) {
      //  A real Ethernet packet
      if (receive_buffer[12] == 8 && receive_buffer[13] == 0 &&
	  receive_buffer_length >= 34) {
	// An IP packet     
      /* Check IP Header Checksum */
      usIPCheckSum = IPCheckSum(receive_buffer+IP_HEADER_OFFSET, IP_HEADER_SIZE);
      if(usIPCheckSum){
       printf("received checksum fail; discarding the packet\n");
      }
      else{
      printf("received checksum successs\n");
      }
    
	if (receive_buffer[23] == 0x11) {
	  // A UDP packet
	  if (receive_buffer_length >= UDP_PACKET_PAYLOAD_OFFSET) {
        /* receive_buffer has max of 1600 bytes. Hence read only 1600 bytes */
        receive_buffer[1599] = 0;
        //put_vga_string(receive_buffer + UDP_PACKET_PAYLOAD_OFFSET,0,0);
        p = receive_buffer + UDP_PACKET_PAYLOAD_OFFSET;
        if(!usIPCheckSum){
            while(*p){
                display_txtOutput(*p);
                p++;
            }
            display_txtNextline();
	    printf("Received: %s\n",
		   receive_buffer + UDP_PACKET_PAYLOAD_OFFSET);
        }
	  }
	} else {
	  printf("Received non-UDP packet\n");
	}
      } else {
	printf("Received non-IP packet\n");
      }
    } else {
      printf("Malformed Ethernet packet\n");
    }

  } else {
    printf("Error receiving packet\n");
  }

  /* Display the number of interrupts on the LEDs */
  interrupt_number++;
  outport(SEG7_DISPLAY_BASE, interrupt_number);

  /* Clear the DM9000A ISR: PRS, PTS, ROS, ROOS 4 bits, by RW/C1 */
  dm9000a_iow(ISR, 0x3F);
			  
  /* Re-enable DM9000A interrupts */
  dm9000a_iow(IMR, INTR_set);
}



#if 1
void hex_print(char* data, int length)
{
    int ptr = 0;
    for(;ptr < length;ptr++)
    {
        printf("0x%02x ",(unsigned char)*(data+ptr));
    }
    printf("\n");
}
#endif



int main()
{
  int width_count = 0, height_count = 0;
  int name_Count = 0;
  
  int curMsgChar = 0;
  alt_u8 key = 0;
  int status = 0;
  unsigned int packet_length;
  unsigned short usIPCheckSum = 0;

  VGA_Ctrl_Reg vga_ctrl_set;
  
  vga_ctrl_set.VGA_Ctrl_Flags.RED_ON    = 1;
  vga_ctrl_set.VGA_Ctrl_Flags.GREEN_ON  = 1;
  vga_ctrl_set.VGA_Ctrl_Flags.BLUE_ON   = 1;
  vga_ctrl_set.VGA_Ctrl_Flags.CURSOR_ON = 0;
  
  Vga_Write_Ctrl(VGA_0_BASE, vga_ctrl_set.Value);
  Set_Pixel_On_Color(1023,1023,1023);
  Set_Pixel_Off_Color(0,0,0);
  Set_Cursor_Color(0,1023,0);

  // Initialize the LCD and display a welcome message
  LCD_Init();
  LCD_Show_Text("4840 Lab 2");

  // Clear the LEDs to zero (will display interrupt count)
  outport(SEG7_DISPLAY_BASE, 0);

  // Initalize the DM9000 and the Ethernet interrupt handler
  DM9000_init(mac_address);
  interrupt_number = 0;
  alt_irq_register(DM9000A_IRQ, NULL, (void*)ethernet_interrupt_handler); 
 
  // Initialize the keyboard
  printf("Please wait three seconds to initialize keyboard\n");
  clear_FIFO();
  switch (get_mode()) {
  case PS2_KEYBOARD:
    break;
  case PS2_MOUSE:
    printf("Error: Mouse detected on PS/2 port\n");
    goto ErrorExit;
  default:
    printf("Error: Unrecognized or no device on PS/2 port\n");
    goto ErrorExit;
  }

  printf("Ready to send messages\n");

  /* Clear the screen */
  for(width_count = 0; width_count <640; width_count ++){
    for(height_count = 0; height_count <480; height_count++){
        Vga_Clr_Pixel(VGA_0_BASE,width_count,height_count);
    }
  }
   
 /* Ask user to input data */
 put_vga_string("Welcome to Chat-4840",0,0);
 put_vga_string("Please enter your name in User Input region (max 4 chars)",0,1);
 
 /* Region for user's input */
 for(width_count = 0; width_count <640; width_count ++){
      Vga_Set_Pixel(VGA_0_BASE,width_count,431);
  }
  put_vga_string("User Input", 0, 27);
  for(width_count = 0; width_count <640; width_count ++){
      Vga_Set_Pixel(VGA_0_BASE,width_count,446);
  }
  
  /* Set Initial Cursor */
  put_vga_char('_',0,28);

  // Clear the payload
  for (curMsgChar=MAX_MSG_LENGTH-1; curMsgChar>0; curMsgChar--) {
    UDP_PACKET_PAYLOAD[curMsgChar] = 0;
  }

  for (;;) { 
    // wait for the user's input and get the make code
    status = read_make_code(&decode_mode, &key);
    if (status == PS2_SUCCESS) {
      // print out the result
      switch ( decode_mode ) {
      case KB_ASCII_MAKE_CODE :
    if((64 < key) && (key < 91)){
        key = key+32;
    }
    
    if(gShiftPressflag){
        shiftTransform(&key);
    }
	
    if(gNameFlag){
        transmit_buffer[name_Count+UDP_PACKET_PAYLOAD_OFFSET] = key;
        name_Count++;
        display_txtInput(key); 
        if(5 == name_Count) /* max name chars is 5*/{
            gNameFlag = 0;
            /* Clear the 2nd line of screen */
            for(width_count = 0; width_count <640; width_count ++){
                for(height_count = 16; height_count <32; height_count++){
                    Vga_Clr_Pixel(VGA_0_BASE,width_count,height_count);
                }
            }
        }
    }
    else{
    	if (curMsgChar < MAX_MSG_LENGTH) { 
    	  UDP_PACKET_PAYLOAD[curMsgChar] = key;
    	  curMsgChar++;
          display_txtInput(key); 
    	}
    }
	break ;
      case KB_LONG_BINARY_MAKE_CODE :
	printf("%s", " LONG ");
	// fall through
      case KB_BINARY_MAKE_CODE :
	switch (key) {
	case  0x5a: //enter key: send the msg
      if(gNameFlag){
        gNameFlag = 0;
        /* Clear the 2nd line of screen */
        for(width_count = 0; width_count <640; width_count ++){
            for(height_count = 16; height_count <32; height_count++){
                Vga_Clr_Pixel(VGA_0_BASE,width_count,height_count);
            }
        }
       display_txtInput_clear(); /* Clear the bottom screen */
      }
      else{
          char *p = NULL;
    	  printf("Msg to Send: "); 
          display_txtInput_clear(); /* Clear the screen */
          /* Make sure you are sending atleast 64 bytes */
          while(curMsgChar < 64){
            UDP_PACKET_PAYLOAD[curMsgChar] = ' ';
            curMsgChar++;
          }
    	  UDP_PACKET_PAYLOAD[curMsgChar++] = 0; // Terminate the string
          p = UDP_PACKET_PAYLOAD - UDP_PACKET_PAYLOAD_NAME_LENGTH;
          while(*p){
              display_txtOutput(*p);
              p++;
          }
          display_txtNextline();
          /* Increment IP packet ID*/
          gIPPacketIDNum++;
          transmit_buffer[IP_PACKET_ID_OFFSET] = gIPPacketIDNum >> 8;
          transmit_buffer[IP_PACKET_ID_OFFSET + 1] = gIPPacketIDNum & 0xff;
          
   
          /* Compute IP Header Checksum */
          usIPCheckSum = IPCheckSum(transmit_buffer+IP_HEADER_OFFSET, IP_HEADER_SIZE);
          transmit_buffer[IP_HEADER_CHECKSUM_OFFSET] = usIPCheckSum >> 8;
          transmit_buffer[IP_HEADER_CHECKSUM_OFFSET+1] = usIPCheckSum & 0xff;
          hex_print(transmit_buffer+IP_HEADER_OFFSET, IP_HEADER_SIZE);
#if 1     
          /* Swap the check sum bytes before checking
             This is because the MSB is in lower address and LSB in higher address */
         //cTemp = transmit_buffer[IP_HEADER_CHECKSUM_OFFSET];
         //transmit_buffer[IP_HEADER_CHECKSUM_OFFSET] = transmit_buffer[IP_HEADER_CHECKSUM_OFFSET+1];
         //transmit_buffer[IP_HEADER_CHECKSUM_OFFSET+1] = cTemp;
         
          /* Check IP Header Checksum */
          usIPCheckSum = IPCheckSum(transmit_buffer+IP_HEADER_OFFSET, IP_HEADER_SIZE);
          if(usIPCheckSum){
            printf("checksum fail\n");
          }
          else{
            printf("checksum successs\n");
          }
          /* Swap back the checsum bytes before sending */
          //cTemp = transmit_buffer[IP_HEADER_CHECKSUM_OFFSET];
          //transmit_buffer[IP_HEADER_CHECKSUM_OFFSET] = transmit_buffer[IP_HEADER_CHECKSUM_OFFSET+1];
          //transmit_buffer[IP_HEADER_CHECKSUM_OFFSET+1] = cTemp;
          hex_print(transmit_buffer+IP_HEADER_OFFSET, IP_HEADER_SIZE);
#endif
          packet_length = UDP_PACKET_PAYLOAD_OFFSET + UDP_PACKET_PAYLOAD_NAME_LENGTH + curMsgChar;
          transmit_buffer[UDP_PACKET_LENGTH_OFFSET] = packet_length >> 8;
          transmit_buffer[UDP_PACKET_LENGTH_OFFSET + 1] = packet_length & 0xff;
          
    	  if (TransmitPacket(transmit_buffer, UDP_PACKET_PAYLOAD_OFFSET + UDP_PACKET_PAYLOAD_NAME_LENGTH + curMsgChar + 1)==DMFE_SUCCESS) { 
    	    printf("\nMessage sent successfully\n");
    	  } else {
    	    printf("\nMessage sending failed\n"); 
    	  }
    	  // reset data
    	  for (curMsgChar=MAX_MSG_LENGTH-1; curMsgChar>0; curMsgChar--) { 
    	    UDP_PACKET_PAYLOAD[curMsgChar] = 0;
    	  }
          
          /* Set the IP CheckSum Fields to Zero */
          transmit_buffer[IP_HEADER_CHECKSUM_OFFSET + 1] = 0x00;
          transmit_buffer[IP_HEADER_CHECKSUM_OFFSET] = 0x00;
    	  printf("Msg to Send: "); 
      }
	  break; 
	case 0x29: //space key
	  UDP_PACKET_PAYLOAD[curMsgChar++] = ' ';
      display_txtInput(' ');
	  break;
    case 0x66: /*backspace key */
      if(curMsgChar){
        curMsgChar--; /* can't go below zero */
      }
      UDP_PACKET_PAYLOAD[curMsgChar] = 0;
      display_txtInput_BackSpace();
      break;
    case 0x6B: /* cursor move left*/
      if(curMsgChar){
        curMsgChar--; /* can't go below zero */
      }
      move_cursor(1);
    break;
    case 0x74: /* cursor move right*/
      if(curMsgChar < MAX_MSG_LENGTH-1){
        curMsgChar++;
      }
      move_cursor(0);
    break;
    case 0x59: /* shift press*/
    case 0x12: /* shift press*/
      gShiftPressflag = 1;
      printf("shift press\n");
    break;

	default:
	  printf(" MAKE CODE :\t%X\n", key ); //print other unknown breakcode
    break;
	}
  		      
	break ;
      case KB_BREAK_CODE :
        switch (key) {
            case 0x59: /* shift release*/
            case 0x12: /* shift release*/
              gShiftPressflag = 0;
              printf("shift release\n");
            break;
            default:
              
            break;
        }
	// do nothing
    break;
      default :
	break ;
      }
    }
    else {
      printf(" Keyboard error ....\n");
    }
  }

  printf("Program terminated normally\n");
  return 0;
    	
 ErrorExit:
  printf("Program terminated with an error condition\n");

  return 1;
}