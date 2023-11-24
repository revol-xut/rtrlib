// https://en.wikipedia.org/wiki/Splay_tree
#include "splaytree.h"

void stree_left_rotate(node **root, node *x) {
    node *y = x->right;
    if (y) {
        x->right = y->left;
        if (y->left) y->left->parent = x;
        y->parent = x->parent;
    }
    
    if (!x->parent) *root = y;
    else if (x == x->parent->left) x->parent->left = y;
    else x->parent->right = y;
    if (y) y->left = x;
    x->parent = y;
}

void stree_right_rotate(node **root, node *x) {
    node *y = x->left;
    if (y) {
        x->left = y->right;
        if (y->right) y->right->parent = x;
        y->parent = x->parent;
    }
    if (!x->parent) *root = y;
    else if (x == x->parent->left) x->parent->left = y;
    else x->parent->right = y;
    if (y) y->right = x;
    x->parent = y;
}

void stree_splay(node **root, node *x) {
    while (x->parent) {
        if (!x->parent->parent) {
            if (x->parent->left == x) stree_right_rotate(root, x->parent);
            else stree_left_rotate(root, x->parent);
        } else if (x->parent->left == x && x->parent->parent->left == x->parent) {
            stree_right_rotate(root, x->parent->parent);
            stree_right_rotate(root, x->parent);
        } else if (x->parent->right == x && x->parent->parent->right == x->parent) {
            stree_left_rotate(root, x->parent->parent);
            stree_left_rotate(root, x->parent);
        } else if (x->parent->left == x && x->parent->parent->right == x->parent) {
            stree_right_rotate(root, x->parent);
            stree_left_rotate(root, x->parent);
        } else {
            stree_left_rotate(root, x->parent);
            stree_right_rotate(root, x->parent);
        }
    }
}

void stree_replace(node **root, node *u, node *v) {
    if (!u->parent) *root = v;
    else if (u == u->parent->left) u->parent->left = v;
    else u->parent->right = v;
    if (v) v->parent = u->parent;
}

node* stree_subtree_minimum(node *u) {
    while (u->left) u = u->left;
    return u;
}

node* stree_subtree_maximum(node *u) {
    while (u->right) u = u->right;
    return u;
}

void stree_insert(node **root, const T key) {
    node *z = *root;
    node *p = NULL;
    
    while (z) {
        p = z;
        if (comp(z->key, key)) z = z->right;
        else z = z->left;
    }
    
    z = (node*)calloc(1, sizeof(node));
    z->parent = p;
    z->key = key;
    
    if (!p) *root = z;
    else if (comp(p->key, z->key)) p->right = z;
    else p->left = z;
    
    stree_splay(root, z);
    //p_size++;
}

node* stree_find(node *root, const T key) {
    node *z = root;
    while (z) {
        if (comp(z->key, key)) z = z->right;
        else if (comp(key, z->key)) z = z->left;
        else return z;
    }
    return NULL;
}
            
void stree_erase(node **root, const T key) {
    node *z = stree_find(*root, key);
    if (!z) return;
    
    stree_splay(root, z);
    
    if (!z->left) stree_replace(root, z, z->right);
    else if (!z->right) stree_replace(root, z, z->left);
    else {
        node *y = stree_subtree_minimum(z->right);
        if (y->parent != z) {
            stree_replace(root, y, y->right);
            y->right = z->right;
            y->right->parent = y;
        }
        stree_replace(root, z, y);
        y->left = z->left;
        y->left->parent = y;
    }
    
    free(z);
    //p_size--;
}

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

T stree_minimum(node *root) { return stree_subtree_minimum(root)->key; }
T stree_maximum(node *root) { return stree_subtree_maximum(root)->key; }

bool empty(node *root) { return root == NULL; }
//unsigned long size(node *root) const { return p_size; }
