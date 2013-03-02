/*
 * CSEE 4840 Lab 2: Keyboard Input and VGA Display Function
 *                  Declarations
 *
 * Manu Dhundi
 *
 */
#ifndef LAB2_H_
#define LAB2_H_

#endif /*LAB2_H_*/

/**********************************************************
 * Read user input and display it in bottom
 * 
*********************************************************/
int display_txtInput(char c);

/**********************************************************
 * Clear the bottom area when data is sent
 * 
*********************************************************/
void display_txtInput_clear(void);

/**********************************************************
 * Backspace
 * 
*********************************************************/
void display_txtInput_BackSpace(void);

/**********************************************************
 * move cursor right if rightFlag == 1; else move left
 * 
*********************************************************/
void move_cursor(int rightFlag);

/**********************************************************
 * make change due to shift being pressed
 * 
*********************************************************/
void shiftTransform(char *c);
