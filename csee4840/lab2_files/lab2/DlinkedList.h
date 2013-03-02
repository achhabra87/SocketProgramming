/*
 * DlinkedList.h
 *
 *  Created on: 2012-2-10
 *      Author: Miao880122
 */

#ifndef DLINKEDLIST_H_
#define DLINKEDLIST_H_

#include <stdio.h>
#include <stdlib.h>
#include "alt_up_ps2_port.h"
//-------------------------------------------------------------------------
struct letter
{
    alt_u8 key;
    struct letter *prev;
    struct letter *next;
};
void create_linklist(struct letter **head, alt_u8 key, struct letter **cursor);
void add_node(struct letter *head, alt_u8 key, struct letter *cursor);
void free_linklist(struct letter **head);
void del_node(struct letter *cursor, struct letter **head, int *first);
void move_cursor_left(struct letter *head, struct letter **cursor);
void move_cursor_right (struct letter *head, struct letter **cursor);
#endif /* DLINKEDLIST_H_ */