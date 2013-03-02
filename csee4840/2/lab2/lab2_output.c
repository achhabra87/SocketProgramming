/*
 * CSEE 4840 Lab 2: Output and VGA Display Functions
 *               
 *
 * Manu Dhundi
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

static int gDisplayWidth = 0;
static int gDisplayHeight = 1;
 
/**********************************************************
 * Display chats on the screen
 * 
*********************************************************/
void display_txtOutput(char c)
{
    int width_count = 0, height_count = 0;
    put_vga_char(c, gDisplayWidth, gDisplayHeight);
    gDisplayWidth++;
    if(gDisplayWidth == 80){
        gDisplayWidth = 0;
        if(gDisplayHeight < 26){
            gDisplayHeight++;
        }
        else{
            /* Clear all data and go back to 2nd line */
            gDisplayHeight = 1;
            for(width_count = 0; width_count <640; width_count ++){
                for(height_count = 17; height_count <431; height_count++){
                    Vga_Clr_Pixel(VGA_0_BASE,width_count,height_count);
                }
            }
        }
    }
    return;
}

/**********************************************************
 * Go to next line on output screen
 * 
*********************************************************/
void display_txtNextline(void)
{
    int width_count = 0, height_count = 0;
    gDisplayWidth = 0;
    if(gDisplayHeight < 26){
            gDisplayHeight++;
    }
    else{
        /* Clear all data and go back to 2nd line */
        gDisplayHeight = 1;
        for(width_count = 0; width_count <640; width_count ++){
            for(height_count = 17; height_count <431; height_count++){
                Vga_Clr_Pixel(VGA_0_BASE,width_count,height_count);
            }
        }
    }
    return;
}
