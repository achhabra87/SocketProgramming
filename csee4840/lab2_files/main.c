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
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#define MAX_MSG_LENGTH 128

// Ethernet MAC address.  Choose the last three bytes yourself
//unsigned char mac_address[6] = { 0x01, 0x60, 0x6E, 0x11, 0x02, 0x0F  };
unsigned char mac_address[6] = { 0x01, 0x60, 0x6E, 0xDA, 0x11, 0x11 };
unsigned int interrupt_number;

unsigned int receive_buffer_length;
unsigned char receive_buffer[1600];

KB_CODE_TYPE decode_mode;

#define UDP_PACKET_PAYLOAD_OFFSET 42
#define UDP_PACKET_LENGTH_OFFSET 38
#define IP_CHECKSUM_OFFSET 40

#define UDP_PACKET_PAYLOAD (transmit_buffer + UDP_PACKET_PAYLOAD_OFFSET)

unsigned char transmit_buffer[] = {
  // Ethernet MAC header
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination MAC address
  0x01, 0x60, 0x6E, 0x11, 0x02, 0x0F, // Source MAC address
  0x08, 0x00,                         // Packet Type: 0x800 = IP
                          
  // IP Header
  0x45,                // version (IPv4), header length = 20 bytes
  0x00,                // differentiated services field
  0x00,0x9C,           // total length: 20 bytes for IP header +
                       // 8 bytes for UDP header + 128 bytes for payload
  0x3d, 0x35,          // packet ID
  0x00,                // flags
  0x00,                // fragment offset
  0x80,                // time-to-live
  0x11,                // protocol: 11 = UDP
  0xa3,0x43,           // header checksum: incorrect
  0xc0,0xa8,0x01,0x01, // source IP address
  0xc0,0xa8,0x01,0xff, // destination IP address
                          
  // UDP Header
  0x67,0xd9, // source port port (26585: garbage)
  0x27,0x2B, // destination port (10027: garbage)
  0x00,0x88, // length (136: 8 for UDP header + 128 for data)
  0x00,0x00, // checksum: 0 = none
                          
  // UDP payload
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

char username[1000];
int user_name_length=0,msg_length=0;
int display_col=0,display_row=0,input_row=22,input_col=0,chat_mode=0;
int traceCursor=0;
  unsigned int row, col;
//int shift_enable;
//////////////////////
const int maxCol = 60;
const int input_row_min=22;
const int input_row_max = 5+ 22;
/////////////////////
//IP Checksum/
unsigned int checksum( int start, int end, int PACKET_OFFSET) 
{
  
    unsigned short word16;
    unsigned int sum=0;
    unsigned int i;
  
    // make 16 bit words out of every two adjacent 8 bit words in the packet
   // and add them up
    transmit_buffer[PACKET_OFFSET+1] = 0x00; 
    transmit_buffer[PACKET_OFFSET] = 0x00 ; 
  
    for (i=start;i<end;i=i+2){
        word16 =((transmit_buffer[i]<<8)&0xFF00)+(transmit_buffer[i+1]&0xFF);
        sum = sum + (unsigned int) word16; 
    }
  
// take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16)
        sum = (sum & 0xFFFF)+(sum >> 16);
    // one's complement the result
    sum = ~sum;
    transmit_buffer[PACKET_OFFSET+1] = (unsigned char)(sum); 
    transmit_buffer[PACKET_OFFSET] = (unsigned char)(sum >>8) ; 
    return sum;
  
}

void cursor_on(unsigned int col,unsigned int row)
{
    int i;
    for(i = 0; i < 8; i++)
    {
        Vga_Set_Pixel(BINARY_VGA_CONTROLLER_0_BASE, 8*col + i, 16*row+15);
    }
}

void cursor_off(unsigned int col,unsigned int row)
{
    int i;
    for(i = 0; i < 8; i++)
    {
        Vga_Clr_Pixel(VGA_0_BASE, 8*col + i, 16*row+15);
    }
}

void updateRowColumn(void)
{
    input_col++;
    if(input_col>=maxCol)
    {
        input_col=0;
        input_row++;
       
        if(input_row>=input_row_max)
        {
            input_row=input_row_min;
            if(chat_mode==1)
            {
                input_col=user_name_length+2;
            }
        }
    }

}





static void ethernet_interrupt_handler() {
  unsigned int receive_status;
  int i;
  
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
    if (receive_buffer[23] == 0x11) {
      // A UDP packet
      if (receive_buffer_length >= UDP_PACKET_PAYLOAD_OFFSET) {
        printf("Received: %s\n",
           receive_buffer+  UDP_PACKET_PAYLOAD_OFFSET);
              
            int u;
            for (u=UDP_PACKET_PAYLOAD_OFFSET; u<receive_buffer_length-8; u++) { 
                

                if(display_col>=maxCol)
                {
                    display_col=0;
                    
                    if(display_row>input_row_min-3)
                    {
                        display_row=0;
                          for (row = 0 ; row < 340 ; row++){
                            for (col = 0 ; col < 640 ; col++){
                                Vga_Clr_Pixel(VGA_0_BASE, col, row);}}
                    }
                    else{
                        display_row++;
                    }
                }
                if(receive_buffer[u]==0)
                {
                    break;
                }
                put_vga_char(receive_buffer[u], display_col, display_row);
                display_col++;
            }
            
            display_row++;
            if(display_row>input_row_min-3)
            {
                display_row=0;
                for (row = 0 ; row < 340 ; row++){
                    for (col = 0 ; col < 640 ; col++){
                        Vga_Clr_Pixel(VGA_0_BASE, col, row);}}
             }
            display_col=0;             
              
         
              
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

int main()
{
  int curMsgChar = 0;
  alt_u8 key = 0;
  int status = 0;
  int shiftKeyEnable=0;
  int flagCol=0,flagRow=0;
  unsigned int packet_length;
  int tempCol,tempRow;




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

  // Print a friendly welcome message
  printf("4840 Lab 2 started\n");

  // Initalize the DM9000 and the Ethernet interrupt handler
  DM9000_init(mac_address);
  interrupt_number = 0;
  int i=0;

       
  
 //alt_irq_register(DM9000A_IRQ, NULL, (void*)ethernet_interrupt_handler); 
 
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

  // Clears the screen whent the program starts
  for (row = 0 ; row < 480 ; row++)
    for (col = 0 ; col < 640 ; col++)
      Vga_Clr_Pixel(VGA_0_BASE, col, row);  
  // Seprates the screen into two parts 
  for (col = 0 ; col < 640 ; col++)
     Vga_Set_Pixel(VGA_0_BASE, col, 350);
  
  

  // Clear the payload
  for (curMsgChar=MAX_MSG_LENGTH-1; curMsgChar>user_name_length; curMsgChar--) {
    UDP_PACKET_PAYLOAD[curMsgChar] = 0;
  }
  flagCol=input_col;
  flagRow=input_row;
    put_vga_string("Please enter your name username:", 0, 20);
  for (;;) { 
    // wait for the user's input and get the make code
    if(chat_mode==1)
    {
        alt_irq_register(DM9000A_IRQ, NULL, (void*)ethernet_interrupt_handler); 
    }
    status = read_make_code(&decode_mode, &key);
    if (status == PS2_SUCCESS) {
      // print out the result
      switch ( decode_mode ) {
      case KB_ASCII_MAKE_CODE :
      if(chat_mode==0)
      {
        if(user_name_length==curMsgChar)
        {
            user_name_length++;
            }
      }
      else{
        traceCursor++;
      msg_length++;
      }
      updateRowColumn();
    key=tolower(key);
    if (shiftKeyEnable == 1)
    {
            if (key >= 'a' && key <= 'z')
                key=toupper(key);
            else if (key == '1') key = '!';
            else if (key == '2') key = '@';
            else if (key == '3') key = '#';
            else if (key == '4') key = '$';
            else if (key == '5') key = '%';
            else if (key == '6') key = '^';
            else if (key == '7') key = '&';
            else if (key == '8') key = '*';
            else if (key == '9') key = '(';
            else if (key == '0') key = ')';
            else if (key == '-') key = '_';
            else if (key == '=') key = '+';
            else if (key == '[') key = '{';
            else if (key == ']') key = '}';
            else if (key == ';') key = ':';
            else if (key == 39) key = 34;
            else if (key == '/') key = '?';
            else if (key == '.') key = '>';
            else if (key == ',') key = '<';
            else if (key == '`') key = '~'; 
                               
       }
      flagCol=input_col;
      flagRow=input_row;
      
    printf("%c", key );
        if(input_col==0 && input_row>=input_row_min+1){
        cursor_off(maxCol,input_row-1);
    }
    else if(input_col==0 && input_row==input_row_min)
    {
        cursor_off(maxCol,input_row_max-1);
    }
    else 
    {
        cursor_off(input_col,input_row);
    }
    cursor_on(input_col+1,input_row);
     put_vga_char(key,input_col,input_row);
    if (curMsgChar < MAX_MSG_LENGTH) { 
      UDP_PACKET_PAYLOAD[curMsgChar] = key;
      curMsgChar++; 
    }
    break ;
      case KB_LONG_BINARY_MAKE_CODE :
    //printf("%s", " LONG ");
    // fall through
      case KB_BINARY_MAKE_CODE ://enter. space and return
    switch (key) {
    case  0x5a: //enter key: send the msg
    
    if(chat_mode==0)
    {   
        if(user_name_length!=0)
        {
            cursor_off(input_col+1,input_row);
            curMsgChar=user_name_length;
            input_col=curMsgChar;
            UDP_PACKET_PAYLOAD[user_name_length]=':';
            curMsgChar++;
            traceCursor++;
            put_vga_char(':',input_col+1,input_row);
            updateRowColumn();
            flagCol=input_col;
            flagRow=input_row;
            cursor_off(input_col,input_row);
            cursor_on(input_col+1,input_row);
            chat_mode=1;
            for (row = 319 ; row < 335 ; row++){
                for (col = 0 ; col < 640 ; col++){
                    Vga_Clr_Pixel(VGA_0_BASE, col, row);}}
        }
    }
    else
    {
        cursor_off(input_col+1,input_row);
        for (row = input_row_min; row < input_row_max ; row++)
        {
            for (col = 0 ; col < maxCol ; col++){
                put_vga_char(' ',col,row);
            }
        }
        input_col=0;input_row=input_row_min; 
        printf("Msg to Send: "); 
        
        UDP_PACKET_PAYLOAD[curMsgChar++] = 0; // Terminate the string
        /*
        int packetId;
        packetId = (transmit_buffer[19] + 1);
        if (packetId < 256)
        {
            transmit_buffer[19] = packetId;
        }
        else
        {
            transmit_buffer[18] = packetId - 255;  
        }  

      transmit_buffer[25]--;
      */
        packet_length = UDP_PACKET_PAYLOAD_OFFSET + curMsgChar;
        transmit_buffer[UDP_PACKET_LENGTH_OFFSET] = packet_length >> 8;
        transmit_buffer[UDP_PACKET_LENGTH_OFFSET + 1] = packet_length & 0xff;
        //checksum(14,34,IP_CHECKSUM_OFFSET);
 /*        for (i=0; i<100000; i++) { 
   TransmitPacket(transmit_buffer, UDP_PACKET_PAYLOAD_OFFSET + curMsgChar + 1);
}*/
        if (TransmitPacket(transmit_buffer, UDP_PACKET_PAYLOAD_OFFSET + curMsgChar + 1)==DMFE_SUCCESS) { 
            //printf("\nMessage sent successfully\n");
            //put_vga_string("Message sent successfully", 0, 27);
            int j;
            for (j=0; j<=msg_length+user_name_length; j++) { 
                
                display_col++;
                if(display_col>=maxCol)
                {
                    display_col=0;
                    display_row++;
                    if(display_row>input_row_min-2)
                    {
                        display_row=0;
                          for (row = 0 ; row < 340 ; row++){
                            for (col = 0 ; col < 640 ; col++){
                                Vga_Clr_Pixel(VGA_0_BASE, col, row);}}
                    }
                }

                put_vga_char(UDP_PACKET_PAYLOAD[j], display_col, display_row);

            }
            display_row++;
            if(display_row>input_row_min-3)
            {
                display_row=0;
                for (row = 0 ; row < 340 ; row++){
                    for (col = 0 ; col < 640 ; col++){
                        Vga_Clr_Pixel(VGA_0_BASE, col, row);}}
                }
            msg_length=0;
            display_col=0;
        } else {
            //printf("\nMessage sending failed\n");
             put_vga_string("Message sending failed", 0, 27);
        } 
            
        
  
  // reset data
        for (curMsgChar=MAX_MSG_LENGTH-1; curMsgChar>user_name_length+1; curMsgChar--) { 
            UDP_PACKET_PAYLOAD[curMsgChar] = 0;
        }
        input_row=input_row_min;
        input_col=0;
        flagCol=input_col;
        flagRow=input_row;
        int i;
        for (i=0;i<=user_name_length;i++)
        {
            updateRowColumn();
            put_vga_char(UDP_PACKET_PAYLOAD[i],input_col,input_row);
        }
        cursor_off(input_col,input_row);
        cursor_on(input_col+1,input_row);
        printf("Msg to Send: "); 
    }
    
      break; 
    case 0x29: //space key
    updateRowColumn();
    if(chat_mode==1)
    {
        msg_length++;
        traceCursor++;
    }
    else{
        if(user_name_length==curMsgChar)
        {
            user_name_length++;
            }
            traceCursor++;
    }
    flagCol=input_col;
    flagRow=input_row;
    cursor_on(input_col+1,input_row);
    if(input_col==0 && input_row>=1){
        cursor_off(maxCol,input_row-1);
    }
    else if(input_col==0 && input_row==input_row_min)
    {
        cursor_off(maxCol,input_row_max-1);
    }
    else 
    {
        cursor_off(input_col,input_row);
    }
    put_vga_char(' ',input_col,input_row);
      UDP_PACKET_PAYLOAD[curMsgChar++] = ' ';
      break;
     //backspace key
     case 0x66:

     
     if(chat_mode==1)
     {
        
        if(curMsgChar>=user_name_length+2){
            UDP_PACKET_PAYLOAD[curMsgChar--] = 0;msg_length--;}
            
        if(input_row==input_row_min )
        {
            if(input_col>=user_name_length+2)
            {
                cursor_off(input_col+1,input_row);
                put_vga_char(' ',input_col,input_row);
                input_col=input_col-1;       
                cursor_on(input_col+1,input_row);
            
            }
        }
        else{
            cursor_off(input_col+1,input_row);
            if(input_col<0)
            {
                input_col=maxCol;
                input_row=input_row-1;
            }
            if(input_row>=input_row_min)
            {
                put_vga_char(' ',input_col,input_row);
                input_col=input_col-1;

                cursor_on(input_col+1,input_row);
            }
        }
    }
    else
    {
        user_name_length--;        
        
        cursor_off(input_col+1,input_row);
        if(input_col<0)
        {
            input_col=maxCol;
            input_row=input_row-1;
        }
        if(input_row>=input_row_min)
        {
            
            put_vga_char(' ',input_col,input_row);
            input_col=input_col-1;

            cursor_on(input_col+1,input_row); 
        }
     }
    
    
    
    /*
                 if(traceCursor!=curMsgChar)
            {
                if(traceCursor<=curMsgChar)
                {
                    tempCol=input_col;
                    tempRow=input_row;
                    for(row=traceCursor;row<curMsgChar;row++)
                    {
                        put_vga_char(UDP_PACKET_PAYLOAD[row+1],tempCol,tempRow);
                        tempCol--;
                        if(tempCol<0)
                        {
                            tempCol=maxCol;
                            tempRow--;
                        }
                    }
                }
            
            }
            else
            {
                UDP_PACKET_PAYLOAD[curMsgChar--] = 0;  
            }
     
     
     
     */
    
    
    
     
     
      break;
      // Shift Keys
     case 0x59:
     case 0x12:
        shiftKeyEnable=1;
      break;
      
     case 0x74:// Right Arrow
        if(input_col== flagCol && input_row == flagRow)
        {
            
        }
        else{
            traceCursor++;
            cursor_off(input_col,input_row);
            input_col=input_col+1;
            if(input_col>maxCol-1)     
            {
                input_col=0;
                input_row=input_row+1;
                if(input_row>input_row_max){
                    input_row=input_row_max;
                    input_col=maxCol;
                }
            }
            cursor_on(input_col,input_row);
        }
        /*
     curMsgChar++;
     cursor_off(input_col,input_row);
  
        input_col=input_col+1;
        if(input_col>maxCol-1)     
        {
            input_col=0;
            input_row=input_row+1;
            if(input_row>input_row_max){
                input_row=input_row_max;
                input_col=maxCol;
            }
        }
     if(input_col>= flagCol+1 && input_row >= flagRow+1)
     {
        input_col=flagCol;
        input_row=flagRow;
     }
     cursor_on(input_col,input_row);*/
     break;
     case 0x6B:// Left Arrow
     if(chat_mode==1 )
     {
        if(traceCursor>=user_name_length+2)
        {
            if(input_row==input_row_min)
            {
                if(input_col>=user_name_length+2)
                {
                    traceCursor--;
                    cursor_off(input_col+1,input_row);
                    cursor_on(input_col,input_row);
                    input_col--;
                }
            }
            else
            {
                traceCursor--;
                cursor_off(input_col+1,input_row);
                cursor_on(input_col,input_row);            
                input_col=input_col-1;
                if(input_col<0)
                {
                    input_col=maxCol;
                    input_row--;
                }
                
        
            }
        }
     }
     else
     {
       
        if(traceCursor>0)
        {
            traceCursor--;
            cursor_off(input_col+1,input_row);
            cursor_on(input_col,input_row);
            if(input_col<0)
            {
                input_col=maxCol;
                input_row=input_row-1;
                if(input_row<input_row_min)
                {
                    input_row=input_row_min;
                    input_col=0;
                }
            }
            input_col=input_col-1;
        }     
    }
     /*
     if(chat_mode==1 )
     {
        if(curMsgChar>=user_name_length+2)
        {
            if(input_row==input_row_min)
            {
                if(input_col>=user_name_length+2)
                {
                    curMsgChar--;
                    cursor_off(input_col+1,input_row);
                    cursor_on(input_col,input_row);
                    input_col--;
                }
            }
            else
            {
                curMsgChar--;
                cursor_off(input_col+1,input_row);
                cursor_on(input_col,input_row);            
                input_col=input_col-1;
                if(input_col<0)
                {
                    input_col=maxCol;
                    input_row--;
                }
                
        
            }
        }
     }
     else
     {
       
        if(curMsgChar>0)
        {
            curMsgChar--;
            cursor_off(input_col+1,input_row);
            cursor_on(input_col,input_row);
            if(input_col<0)
            {
                input_col=maxCol;
                input_row=input_row-1;
                if(input_row<input_row_min)
                {
                    input_row=input_row_min;
                    input_col=0;
                }
            }
            input_col=input_col-1;
        }     
    }     
       */ 
      break;
//  default:
     // printf(" MAKE CODE :\t%X\n", key ); //print other unknown breakcode
    }
              
    break ;
      case KB_BREAK_CODE :
      switch(key){
      case 0x59:
      case 0x12:
        shiftKeyEnable=0;
      break;
      default:
      break;
      }
    // do nothing
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
