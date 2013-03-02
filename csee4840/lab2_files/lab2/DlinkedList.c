/*
 * DlinkedList.c
 *
 *  Created on: 2012-2-10
 *      Author: Shangru Li
 *      Some of the code of doubly linked list are from C++ text book on datastructure
 *		using a linked list as the following advantages,
 *		when adding or deleting message in the middle of the input message, there is no need for
 *		shift the right side to right on each character in the array.
 *
 */

#include "DlinkedList.h"

void create_linklist(struct letter **head, alt_u8 key, struct letter **cursor)
{
    *head = (struct letter *)malloc(sizeof(struct letter));
    (*head)->key = key;
    (*head)->prev = NULL;
    (*head)->next = NULL;
    *cursor = NULL;
}
//-------------------------------------------------------------------------
void add_node(struct letter *head, alt_u8 key, struct letter *cursor)
{
    // add some letter into the linklist
    struct letter *p;
    struct letter *add;
    add = (struct letter *)malloc(sizeof(struct letter));
    add->key = key;
    if(cursor == NULL)
    { // cursor points at the end of the linklist
        p = head;
        while(p->next)
        {
            p = p->next;
        }
        p->next = add;
        add->prev = p;
        add->next = NULL;
    }
    else
    {
        if(cursor == head)
        { // cursor points at the head of the linklist
        	printf ("INT");
            add->next = head;
            head->prev = add;
            add->prev = NULL;
            head = add;
            //printf ("\n%c", (head->key));
            //printf ("\n%c", cursor->key);
            cursor = add->next;
        }
        else
        { // cursor points at some letter in the middle of the linklist
            cursor->prev->next = add;
            add->prev = cursor->prev;
            add->next = cursor;
            cursor->prev = add;
        }
    }
}
//-------------------------------------------------------------------------
void free_linklist(struct letter **head)
{
    // free the memory of the linklist
    struct letter *p1 = *head;
    struct letter *p2 = p1;
    *head = NULL;
    while(p1)
    {
        p1 = p1->next;
        p1->prev = NULL;
        p2->next = NULL;
        free(p2);
        p2 = p1;
    }
}
//-------------------------------------------------------------------------
void del_node(struct letter *cursor, struct letter **head, int *init)
{
    // delete the node at which the cursor points
    struct letter *delete;
    struct letter *p;
    if(cursor == NULL)
    {
        delete = *head;
        while(delete->next)
        {
            delete = delete->next;
        }
        if(delete != *head)
        {
            delete->prev->next = NULL;
            delete->prev = NULL;
        }
        else
        {
            *head = NULL;
            *init = 0;
        }
        free(delete);
    }
    else
    {
        if(cursor != *head)
        {
            delete = cursor->prev;
            if(delete != *head)
            {
                p = delete->prev;
                p->next = cursor;
                cursor->prev = p;
                delete->prev = NULL;
                delete->next = NULL;
                free(delete);
            }
            else
            {
                *head = (*head)->next;
                (*head)->prev = NULL;
                delete->next = NULL;
                free(delete);
            }
        }
    }
}

void move_cursor_left(struct letter *head, struct letter **cursor){
	if (*cursor!=NULL){
		if(*cursor!=head)
			*cursor = (*cursor) ->prev;
	}
	else{
		*cursor = head;
		while((*cursor)->next){
			*cursor = (*cursor)->next;
		}
	}
}

void move_cursor_right (struct letter *head, struct letter **cursor){
	if(*cursor!=NULL){
		*cursor = (*cursor)->next;
	}
}

//-------------------------------------------------------------------------


