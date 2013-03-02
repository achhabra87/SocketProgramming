/*
 * "Hello World" example.
 *
 * This example prints 'Hello from Nios II' to the STDOUT stream. It runs on
 * the Nios II 'standard', 'full_featured', 'fast', and 'low_cost' example
 * designs. It runs with or without the MicroC/OS-II RTOS and requires a STDOUT
 * device in your system's hardware.
 * The memory footprint of this hosted application is ~69 kbytes by default
 * using the standard reference design.
 *
 * For a reduced footprint version of this template, and an explanation of how
 * to reduce the memory footprint for a given application, see the
 * "small_hello_world" template.
 *
 */


#include <stdio.h>



#define center_position_x_y (*(volatile unsigned int*) 0x00101008)

int main()
{
    int xPosition = 320;
    int yPosition = 240;
    
    int x_value = 1;
    int y_value = 1;
    
    int radius = 16;
    int topBound = 0 + radius;
    int bottomBound = 479 - radius;
    int leftBound = 0 + radius;
    int rightBound = 639 - radius;
    int time=0;
    
    for (;;)
    {
        if(time==4500)
        {
            
        
            if (xPosition+x_value <= leftBound || xPosition+x_value >= rightBound)
            {
                x_value = -x_value;
            }
            else if (yPosition+y_value <= topBound || yPosition+y_value >= bottomBound)
            {
                y_value = -y_value;
            }
        
            xPosition = xPosition + x_value;
            yPosition = yPosition + y_value;
            center_position_x_y = yPosition + (xPosition<<10);
            time=0;
        }
        else
        {
            time++;
        }
    }
    
}
