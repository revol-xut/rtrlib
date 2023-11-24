#ifndef SPLAY_TREE
#define SPLAY_TREE

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#define T uint32_t
#define comp(a,b) ((b)>(a))

typedef struct node {
    struct node *left, *right;
    struct node *parent;
    T key;
} node;


void stree_left_rotate(node **root, node *x);

void stree_right_rotate(node **root, node *x);

void stree_splay(node **root, node *x);

void stree_replace(node **root, node *u, node *v);

node* stree_subtree_minimum(node *u);

node* stree_subtree_maximum(node *u);

void stree_insert(node **root, const T key);

node* stree_find(node *root, const T key);

void stree_erase(node **root, const T key);

/* //the alternative implementation
    void erase(const T &key) {
            node *z = stree_find(key);
            if (!z) return;
            
            stree_splay(z);
            
            node *s = z->left;
            node *t = z->right;
            delete z;
            
            node *sMax = NULL;
            if (s) {
                    s->parent = NULL;
                    sMax = stree_subtree_maximum(s);
                    stree_splay(sMax);
                    root = sMax;
            }
            if (t) {
                    if (s)
                            sMax->right = t;
                    else
                            root = t;
                    t->parent = sMax;
            }
            
            p_size--;
    }
*/

T stree_minimum(node *root);
T stree_maximum(node *root);

bool empty(node *root);
//unsigned long size(node *root) const { return p_size; }

#endif // SPLAY_TREE
