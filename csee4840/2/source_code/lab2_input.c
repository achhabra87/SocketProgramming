/*
 * CSEE 4840 Lab 2: Keyboard Input and VGA Display Functions
 *
 * Manu Dhundi
 *
 */
 
#include "basic_io.h" /* For printf() */
#include "VGA.h" /* VGA display functions() */

static int gDisplayWidth = 0; /* Current Display Width */
static int gDisplayHeight = 28; /* Current Display Height */


/**********************************************************
 * Display the cursor at (gDisplayWidth,gDisplayHeight)
 * 
*********************************************************/
static void display_cursor(int rightFlag)
{
    int width_count = 0;
    if(rightFlag){/* Clear the cursor from its previous right position */
        if(gDisplayWidth == 79){ /* Delete cursor in next line */
            for(width_count = 0; width_count <8; width_count ++){
                Vga_Clr_Pixel(VGA_0_BASE, width_count,
                                (gDisplayHeight)*16+31);
            }
        }
        else{
            for(width_count = 0; width_count <8; width_count ++){
                Vga_Clr_Pixel(VGA_0_BASE,(gDisplayWidth+1)*8 + width_count,
                                (gDisplayHeight)*16+15);
            } 
        }
    }
    else{/* Clear the cursor from its previous left position */
        if(gDisplayWidth == 1){ /* Delete cursor in previous line */
            for(width_count = 0; width_count <8; width_count ++){
                Vga_Clr_Pixel(VGA_0_BASE, 639-width_count,
                                (gDisplayHeight)*16-1);
            }
        }
        for(width_count = 0; width_count <8; width_count ++){
            Vga_Clr_Pixel(VGA_0_BASE,(gDisplayWidth-1)*8 + width_count,
                            (gDisplayHeight)*16+15);
        } 
    }
    
    /* Put the cursor at (gDisplayWidth,gDisplayHeight) */
    for(width_count = 0; width_count <8; width_count ++){
            Vga_Set_Pixel(VGA_0_BASE,(gDisplayWidth)*8 + width_count,
                            (gDisplayHeight)*16+15);
    } 
}


/**********************************************************
 * move cursor from right if rightFlag == 1; 
 * else move from left
 * (for arrow keys)
*********************************************************/
void move_cursor(int rightFlag)
{
    if(rightFlag){
        if(gDisplayWidth){
            gDisplayWidth--;
        }
        else{
            if(28 == gDisplayHeight){ /* No data on screen */
            }
            else{/* Go to end of last line */
                gDisplayHeight--;
                gDisplayWidth = 79;
            }
        }
    }    
    else{
        if(gDisplayWidth == 80){
            gDisplayWidth = 0;
            if(gDisplayHeight == 28){
                gDisplayHeight++;
            }
            else{
                /* Go back to last 2nd line */
                gDisplayHeight = 28;
            }
        }
        else{
            gDisplayWidth++;
        }
    }
    display_cursor(rightFlag);
}

/**********************************************************
 * Read user input and display it in bottom
 * 
*********************************************************/
void display_txtInput(char c)
{
    int width_count = 0, height_count = 0;
    put_vga_char(c, gDisplayWidth, gDisplayHeight);
    gDisplayWidth++;
    if(gDisplayWidth == 80){
        gDisplayWidth = 0;
        if(gDisplayHeight == 28){
            gDisplayHeight++;
        }
        else{
            /* Clear all data and go back to last 2nd line */
            gDisplayHeight = 28;
            for(width_count = 0; width_count <640; width_count ++){
                for(height_count = 447; height_count <480; height_count++){
                    Vga_Clr_Pixel(VGA_0_BASE,width_count,height_count);
                }
            }
        }
    }
    /* Display Cursor */
    display_cursor(0); /* 0 since cursor is moving from left */
    return;
}

/**********************************************************
 * Clear the bottom area when data is sent
 * 
*********************************************************/
void display_txtInput_clear(void)
{
    int width_count = 0, height_count = 0;
    for(width_count = 0; width_count <640; width_count ++){
        for(height_count = 447; height_count <480; height_count++){
            Vga_Clr_Pixel(VGA_0_BASE,width_count,height_count);
        }
    }
    gDisplayWidth = 0;
    gDisplayHeight = 28;
   /* Display Cursor */
    display_cursor(1); /* 1 since cursor is moving from right */
}

/**********************************************************
 * Backspace
 * 
*********************************************************/
void display_txtInput_BackSpace(void)
{
    int width_count = 0, height_count = 0;
    if(gDisplayWidth){
        gDisplayWidth--;
    }
    else{
        if(28 == gDisplayHeight){ /* No data on screen */
        }
        else{/* Go to end of last line */
            gDisplayHeight--;
            gDisplayWidth = 79;
        }
    }
    
    /* Clear the previous character */
    for(width_count = 0; width_count <8; width_count ++){
        for(height_count = 0; height_count <16; height_count++){
            Vga_Clr_Pixel(VGA_0_BASE,gDisplayWidth*8 + width_count,
                         gDisplayHeight*16 + height_count);
        }
    }
    /* Display Cursor */
    display_cursor(1); /* 1 since cursor is moving from right */
    return;
}

/**********************************************************
 * make change due to shift being pressed
 * 
*********************************************************/
void shiftTransform(char *c)
{
    char key = *c;

    /* If alphabet and lower case, then change it to upper-case */
    if((123 > key) && (key > 96)){
        key = key-32;
    }
    else{ /* non alphabets */
        switch(key){
            case '1':
                key = '!';
            break;
            case '2':
                key = '@';
            break;
            case '3':
                key = '#';
            break;
            case '4':
                key = '$';
            break;
            case '5':
                key = '%';
            break;
            case '6':
                key = '^';
            break;
            case '7':
                key = '&';
            break;
            case '8':
                key = '*';
            break;
            case '9':
                key = '(';
            break;
            case '0':
                key = ')';
            break;
            case '-':
                key = '_';
            break;
            case '=':
                key = '+';
            break;
            case '[':
                key = '{';
            break;
            case ']':
                key = '}';
            break;
            case '\\':
                key = '|';
            break;
            case ';':
                key = ':';
            break;
            case '\'':
                key = '\"';
            break;
            case '/':
                key = '?';
            break;
            case '.':
                key = '>';
            break;
            case ',':
                key = '<';
            break;
            case '`':
                key = '~';
            break;
            default:
                printf("Shift transform cannot be applied !!\n");
            break;       
        }
    } 
    *c = key; /* Copy the changed value of key*/
}

