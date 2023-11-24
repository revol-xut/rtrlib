/*
* This file is part of RTRlib.
*
* This file is subject to the terms and conditions of the MIT license.
* See the file LICENSE in the top level directory for more details.
*
* Website: http://rtrlib.realmv6.org/
*/

#ifndef RTR_ASPA_TREE_H
#define RTR_ASPA_TREE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>


// #include "kbtree_aspa.h"
// #define aspa_tree kbtree_aspa_t

// #include "../aspa.h"
#ifndef RTR_ASPA_TREE_INIT
#define RTR_ASPA_TREE_INIT
// KBTREE_INIT(aspa, uint32_t, kb_generic_cmp);
#include "kbtree.h"
__KB_TREE_T(aspa)
typedef kbtree_aspa_t aspa_tree;
#endif
#include "splaytree.h"


/**
 * @brief Struct which is similar in function to std::vector from C++.
 * If the vector is running full a larger chunk of memory is allocated and the data is copied over.
 */

#ifndef RTR_ASPA_RECORD
#define RTR_ASPA_RECORD
struct aspa_record {
	int32_t is_internal;
	uint32_t customer_asn;
	size_t provider_count;
	uint32_t *provider_asns;
};
struct aspa_store_record {
	int32_t is_internal;
	uint32_t customer_asn;
	size_t provider_count;
	uint32_t *provider_asn_array;
	node *provider_asn_tree;
};
#endif


// defines struct kbtree_aspa_t

/**
 * @brief Creates an vector object
 * @param[vector_pointer] the pointer to the newly created pointer will be written to *vector_pointer
 * @result Valid pointer to an aspa_tree struct
 * @result Null On error.
 */
int aspa_tree_create(aspa_tree **aspa_tree);

/**
 * @brief Deletes the given vector
 * @param[vector] aspa_vector which will be deleted
 * @result 0 On success.
 * @result -1 On error.
 */
int aspa_tree_free(aspa_tree *aspa_tree);

/**
 * @brief adds a new aspa record to the list
 * @param[vector] aspa_vector into which the value will be inserted
 * @param[value] uin32_t value which will be inserted
 * @result 0 On success.
 * @result -1 On error.
 */
int aspa_tree_insert(aspa_tree *aspa_tree, struct aspa_store_record *record);

/**
 * @brief deletes the element at the index
 * @param[vector] aspa_vector from where the element should be removed
 * @param[index] index of the element which should be removed
 * @result 0 On success.
 * @result -1 On error.
 */
int aspa_tree_free_at(aspa_tree *aspa_tree, struct aspa_store_record *record);

/**
 * @brief returns the index in the vector for a given customer as number (CAS)
 * @param[vector] aspa_vector in which the algorithm will search
 * @param[custom_as] value for which will be searched
 * @result index of the element on success
 * @result -1 On error or not if the element coulnd't be located
 */
struct aspa_store_record *aspa_tree_find(aspa_tree *aspa_tree, uint32_t customer_asn);

void aspa_tree_itr_first(aspa_tree *aspa_tree, kbitr_t *itr);

int aspa_tree_itr_next(aspa_tree *aspa_tree, kbitr_t *itr);

#endif
