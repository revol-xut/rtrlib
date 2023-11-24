/*
* This file is part of RTRlib.
*
* This file is subject to the terms and conditions of the MIT license.
* See the file LICENSE in the top level directory for more details.
*
* Website: http://rtrlib.realmv6.org/
*/

#ifndef RTR_ASPA_TREE_C
#define RTR_ASPA_TREE_C

#include "aspa_tree.h"

#include "kbtree.h"

#define cmp_customer_asn(a,b) (((b).customer_asn < (a).customer_asn) - ((a).customer_asn < (b).customer_asn))
KBTREE_INIT(aspa, struct aspa_store_record, cmp_customer_asn);


/**
 * @brief Struct which is similar in function to std::vector from C++.
 * If the vector is running full a larger chunk of memory is allocated and the data is copied over.
 */

// defines struct kbtree_aspa_t

/**
 * @brief Creates an vector object
 * @param[vector_pointer] the pointer to the newly created pointer will be written to *vector_pointer
 * @result Valid pointer to an aspa_array struct
 * @result Null On error.
 */
int aspa_tree_create(aspa_tree **aspa_tree) {
    size_t k = 6;
    size_t s = (k*2+1) * (sizeof(void*) + sizeof(struct aspa_store_record));
    *aspa_tree = kb_init(aspa, s);
    if (*aspa_tree == NULL) return -1;
    return 0;
}

/**
 * @brief Deletes the given vector
 * @param[vector] aspa_vector which will be deleted
 * @result 0 On success.
 * @result -1 On error.
 */
int aspa_tree_free(aspa_tree *aspa_tree) {
    kb_destroy(aspa, aspa_tree);
    return 0;
}

/**
 * @brief adds a new aspa record to the list
 * @param[vector] aspa_vector into which the value will be inserted
 * @param[value] uin32_t value which will be inserted
 * @result 0 On success.
 * @result -1 On error.
 */
int aspa_tree_insert(aspa_tree *aspa_tree, struct aspa_store_record *record) {
    kb_putp(aspa, aspa_tree, record);
    return 0;
}

/**
 * @brief deletes the element at the index
 * @param[vector] aspa_vector from where the element should be removed
 * @param[index] index of the element which should be removed
 * @result 0 On success.
 * @result -1 On error.
 */
int aspa_tree_free_at(aspa_tree *aspa_tree, struct aspa_store_record *record) {
    kb_delp(aspa, aspa_tree, record);
    return 0;
}

/**
 * @brief returns the index in the vector for a given customer as number (CAS)
 * @param[vector] aspa_vector in which the algorithm will search
 * @param[custom_as] value for which will be searched
 * @result index of the element on success
 * @result -1 On error or not if the element coulnd't be located
 */
struct aspa_store_record *aspa_tree_find(aspa_tree *aspa_tree, uint32_t customer_asn) {
    struct aspa_store_record search;
    search.customer_asn = customer_asn;
    struct aspa_store_record *key = kb_get(aspa, aspa_tree, search);
    //kbnode_t *x = __KB_PTR(b
    return key;
}

void aspa_tree_itr_first(aspa_tree *aspa_tree, kbitr_t *itr) {
    kb_itr_first(aspa, aspa_tree, itr);
}

int aspa_tree_itr_next(aspa_tree *aspa_tree, kbitr_t *itr) {
    return kb_itr_next(aspa, aspa_tree, itr);
}

#endif
