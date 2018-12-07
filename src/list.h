#ifndef _LISTOSOS_H__
#define _LISTOSOS_H__
typedef struct list_t
{
    struct list_t *next, *prev;
} list_t;

static inline void list_init(list_t * list)
{
    list->next = list;
    list->prev = list;
}

static inline int list_empty(list_t * list)
{
    return list->next == list;
}

static inline void list_insert(list_t * link, list_t * new_link)
{
    new_link->prev = link->prev;
    new_link->next = link;
    new_link->prev->next = new_link;
    new_link->next->prev = new_link;
}

static inline void list_append(list_t * list, list_t * new_link)
{
    list_insert((list_t *) list, new_link);
}

static inline void list_prepend(list_t * list, list_t * new_link)
{
    list_insert(list->next, new_link);
}

static inline void list_remove(list_t * link)
{
    link->prev->next = link->next;
    link->next->prev = link->prev;
}

#define list_entry(link, type, member) \
    ((type *)((char *)(link)-(unsigned long)(&((type *)0)->member)))

#define list_head(list, type, member)        \
    list_entry((list)->next, type, member)

#define list_tail(list, type, member)        \
    list_entry((list)->prev, type, member)

#define list_next(elm, member)                    \
    list_entry((elm)->member.next, typeof(*elm), member)

#define list_for_each_entry(pos, list, member)            \
    for (pos = list_head(list, typeof(*pos), member);    \
         &pos->member != (list);                \
         pos = list_next(pos, member))

#define list_for_each_safe(pos, n, head, member) \
    for (pos = list_head(head, typeof(*pos), member), n = list_next(pos, member); \
        &pos->member != (head); \
        pos = n, n = list_next(pos, member))

/*
void testcase()
{
    typedef struct test_list_t
    {
        int val;
        list_t link;
        int val2;
    }test_list_t;
    int i;
    test_list_t header;
    list_init(&header.link);
    test_list_t *anode, *tmp;
    for(i=0;i<100;i++)
    {
       anode = malloc(sizeof(test_list_t));
       anode->val = i+1;
       list_append(&header.link, &anode->link);
    }

    list_for_each_entry(anode, &header.link, link) {
        printf("item %d\n", anode->val);
    }

    list_for_each_safe(anode, tmp, &header.link, link) {
        printf("freeing item %d\n", anode->val);
        list_remove(&anode->link);
        free(anode);
    }
}
*/
#endif
