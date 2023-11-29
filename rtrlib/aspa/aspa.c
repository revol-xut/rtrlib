/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#include "aspa_array/aspa_array.h"
#include "aspa_private.h"

#include "rtrlib/lib/alloc_utils_private.h"
#include "rtrlib/rtrlib_export_private.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

RTRLIB_EXPORT size_t aspa_size_of_aspa_record(const struct aspa_record *record)
{
	return sizeof(struct aspa_record) + sizeof(*record->provider_asns) * record->provider_count;
}

static void aspa_table_notify_clients(struct aspa_table *aspa_table, const struct aspa_record *record,
				      const struct rtr_socket *rtr_socket, const bool added)
{
	if (aspa_table->update_fp) {
		// Realloc in order not to expose internal record
		size_t record_size = aspa_size_of_aspa_record(record);
		struct aspa_record *copy = lrtr_malloc(record_size);
		memcpy(copy, record, record_size);
		aspa_table->update_fp(aspa_table, *copy, rtr_socket, added);
	}
}

RTRLIB_EXPORT void aspa_table_init(struct aspa_table *aspa_table, aspa_update_fp update_fp)
{
	aspa_table->update_fp = update_fp;
	aspa_table->store = NULL;
	pthread_rwlock_init(&(aspa_table->lock), NULL);
}

static int aspa_store_insert(struct aspa_store_node **store, struct rtr_socket *rtr_socket,
			     struct aspa_array *aspa_array)
{
	// Allocate new node
	struct aspa_store_node *new = lrtr_malloc(sizeof(struct aspa_store_node));

	if (new == NULL)
		return ASPA_ERROR;

	// Store socket and ASPA array
	new->rtr_socket = rtr_socket;
	new->aspa_array = aspa_array;

	if (*store == NULL) {
		*store = new;
		(*store)->next = NULL;
	} else {
		// prepend new node
		new->next = *store;
		*store = new;
	}

	return ASPA_SUCCESS;
}

static void aspa_store_remove(struct aspa_store_node **head, struct rtr_socket *rtr_socket)
{
	if (head == NULL || *head == NULL)
		return;

	// If first node matches
	if (*head != NULL && (*head)->rtr_socket == rtr_socket) {
		struct aspa_store_node *tmp = *head;
		*head = (*head)->next;
		lrtr_free(tmp);
		return;
	}

	struct aspa_store_node *node = *head;
	struct aspa_store_node *prev;

	// First node is guaranteed not to match
	do {
		prev = node;
		node = node->next;
	} while (node != NULL && node->rtr_socket != rtr_socket);

	if (node == NULL)
		return;

	prev->next = node->next;
	lrtr_free(node);
}

static struct aspa_array **aspa_store_search(struct aspa_store_node **node, const struct rtr_socket *rtr_socket)
{
	if (node == NULL || *node == NULL)
		return NULL;

	//	struct aspa_store_node *node = *head;

	while (*node != NULL) {
		if ((*node)->rtr_socket == rtr_socket) {
			return &(*node)->aspa_array;
		}
		node = &(*node)->next;
	}

	return NULL;
}

RTRLIB_EXPORT void aspa_table_free(struct aspa_table *aspa_table, bool notify)
{
	// To destroy the lock, first acquire the lock
	pthread_rwlock_wrlock(&aspa_table->lock);

	struct aspa_store_node *node;

	// Free store
	while (aspa_table->store != NULL) {
		node = aspa_table->store;

		if (notify) {
			// Notify clients about these records being removed
			for (size_t i = 0; i < node->aspa_array->size; i++)
				aspa_table_notify_clients(aspa_table, &(node->aspa_array->data[i]), node->rtr_socket,
							  false);
		}

		aspa_table->store = aspa_table->store->next;
		lrtr_free(node);
	}

	aspa_table->store = NULL;

	pthread_rwlock_unlock(&aspa_table->lock);
	pthread_rwlock_destroy(&aspa_table->lock);
}

static int cmpfunc (const void * a, const void * b) {
   return ( *(uint32_t*)a - *(uint32_t*)b );
}

RTRLIB_EXPORT int aspa_table_add(struct aspa_table *aspa_table, struct aspa_record *record,
				 struct rtr_socket *rtr_socket, bool replace)
{
	if (!aspa_table)
		return ASPA_ERROR;

	pthread_rwlock_wrlock(&aspa_table->lock);

	struct aspa_array *array;

    qsort(record->provider_asns, record->provider_count, sizeof(uint32_t), cmpfunc);

    for (int j = 0; j < ASPA_RECORD_CACHE_SIZE; j++) {
        record->provider_asns_prio[j] = 0;
    }

	// Find the socket's corresponding aspa_array.
	// If fast lookup suceeds (rtr_socket->aspa_table == aspa_table),
	// access rtr_socket->aspa_array directly,
	// perform lookup on aspa_table->store insted.

	// Use fast lookup
	if (rtr_socket->aspa_table == aspa_table) {
		// Check if an ASPA array exists for this socket
		if (rtr_socket->aspa_array == NULL) {
			// Create a new ASPA array, store that array algonside with the socket in the table
			if (aspa_array_create(&rtr_socket->aspa_array) < 0 ||
			    aspa_store_insert(&aspa_table->store, rtr_socket, rtr_socket->aspa_array) != ASPA_SUCCESS) {
				pthread_rwlock_unlock(&aspa_table->lock);
				return ASPA_ERROR;
			}
		}

		array = rtr_socket->aspa_array;
	} else {
		// This isn't the primary table (not the table the socket holds a reference to)
		// Find node matching the given socket
		array = *aspa_store_search(&aspa_table->store, rtr_socket);

		if (array == NULL) {
			// Create a new ASPA array, store that array algonside with the socket in the table
			if (aspa_array_create(&array) < 0 ||
			    aspa_store_insert(&aspa_table->store, rtr_socket, array) != ASPA_SUCCESS) {
				pthread_rwlock_unlock(&aspa_table->lock);
				return ASPA_ERROR;
			}
		}
	}

	// Insert record aspa_array
	// TODO: This function does not handle duplicates/replacing the record
	if (aspa_array_insert(array, *record) < 0) {
		pthread_rwlock_unlock(&aspa_table->lock);
		return ASPA_ERROR;
	}

	pthread_rwlock_unlock(&aspa_table->lock);

	// Notify clients that the record has been added
	aspa_table_notify_clients(aspa_table, record, rtr_socket, true);

	return ASPA_SUCCESS;
}

RTRLIB_EXPORT int aspa_table_remove(struct aspa_table *aspa_table, struct aspa_record *record,
				    struct rtr_socket *rtr_socket)
{
	if (!aspa_table)
		return ASPA_ERROR;

	pthread_rwlock_wrlock(&aspa_table->lock);

	struct aspa_array *array;

	// Find the socket's corresponding aspa_array.
	// If fast lookup suceeds (rtr_socket->aspa_table == aspa_table),
	// access rtr_socket->aspa_array directly,
	// perform lookup on aspa_table->store insted.

	// Use fast lookup
	if (rtr_socket->aspa_table == aspa_table) {
		// Check if an ASPA array exists for this socket
		if (rtr_socket->aspa_array == NULL) {
			pthread_rwlock_unlock(&aspa_table->lock);
			return ASPA_ERROR;
		}

		array = rtr_socket->aspa_array;
	} else {
		// This isn't the primary table (not the table the socket holds a reference to)
		// Find node matching the given socket
		array = *aspa_store_search(&aspa_table->store, rtr_socket);

		if (array == NULL) {
			pthread_rwlock_unlock(&aspa_table->lock);
			return ASPA_ERROR;
		}
	}

	size_t i = aspa_array_search(array, record->customer_asn);

	if (i < 0) {
		pthread_rwlock_unlock(&aspa_table->lock);
		return ASPA_RECORD_NOT_FOUND;
	}

	// Remove record aspa_array
	if (aspa_array_free_at(array, i) < 0) {
		pthread_rwlock_unlock(&aspa_table->lock);
		return ASPA_ERROR;
	}

	pthread_rwlock_unlock(&aspa_table->lock);

	// Notify clients that the record has been removed
	aspa_table_notify_clients(aspa_table, record, rtr_socket, false);

	return ASPA_SUCCESS;
}

RTRLIB_EXPORT int aspa_table_src_remove(struct aspa_table *aspa_table, struct rtr_socket *rtr_socket)
{
	pthread_rwlock_rdlock(&aspa_table->lock);

	struct aspa_array *array = *aspa_store_search(&aspa_table->store, rtr_socket);

	// Try to find array with fast lookup
	if (array == NULL && rtr_socket->aspa_table == aspa_table) {
		array = rtr_socket->aspa_array;
		rtr_socket->aspa_array = NULL;
	}

	if (array == NULL) {
		// Doesn't exist anymore
		pthread_rwlock_unlock(&(aspa_table->lock));
		return ASPA_SUCCESS;
	}

	// Notify clients about these records being removed
	for (size_t i = 0; i < array->size; i++)
		aspa_table_notify_clients(aspa_table, &(array->data[i]), rtr_socket, false);

	// Remove node for socket
	aspa_store_remove(&aspa_table->store, rtr_socket);

	// Release all records associated with the socket
	if (aspa_array_free(array) < 0) {
		pthread_rwlock_unlock(&(aspa_table->lock));
		return ASPA_ERROR;
	}

	pthread_rwlock_unlock(&(aspa_table->lock));
	return ASPA_SUCCESS;
}

int aspa_table_src_move(struct aspa_table *dst, struct aspa_table *src, struct rtr_socket *rtr_socket, bool notify_dst,
			bool notify_src)
{
	if (dst == NULL || src == NULL || rtr_socket == NULL)
		return ASPA_ERROR;

	pthread_rwlock_wrlock(&dst->lock);
	pthread_rwlock_wrlock(&src->lock);

	struct aspa_array *new_array = *aspa_store_search(&src->store, rtr_socket);
	struct aspa_array **old_array_ptr = aspa_store_search(&dst->store, rtr_socket);
	struct aspa_array *old_array = *old_array_ptr;

	if (new_array == NULL) {
		pthread_rwlock_unlock(&src->lock);
		pthread_rwlock_unlock(&dst->lock);
		return ASPA_ERROR;
	}

	int res = ASPA_SUCCESS;

	if (old_array == NULL) {
		// If destination table has no aspa_array associated to the given socket
		res = aspa_store_insert(&dst->store, rtr_socket, new_array);
	} else {
		// Destination table has an aspa_array associated to the given socket
		// Replace ref with new array
		*old_array_ptr = new_array;
	}

	// Remove socket from source table's store
	aspa_store_remove(&src->store, rtr_socket);

	// We may need to replace the aspa_array reference in rtr_socket too
	if (rtr_socket->aspa_table == src) {
		// Socket is associated with source table, remove reference since
		// the array is being moved to the destination table
		rtr_socket->aspa_array = NULL;
	} else if (rtr_socket->aspa_table == dst) {
		// Socket is associated with the destination table, replace
		// with new one
		rtr_socket->aspa_array = new_array;
	}

	pthread_rwlock_unlock(&src->lock);
	pthread_rwlock_unlock(&dst->lock);

	if (notify_src)
		// Notify src clients their records are being removed
		for (size_t i = 0; i < new_array->size; i++)
			aspa_table_notify_clients(src, &(new_array->data[i]), rtr_socket, false);

	if (old_array != NULL) {
		if (notify_dst)
			// Notify dst clients of their existing records are being removed
			for (size_t i = 0; i < old_array->size; i++)
				aspa_table_notify_clients(dst, &(old_array->data[i]), rtr_socket, false);

		// Free the old array
		aspa_array_free(old_array);
	}

	if (notify_dst)
		// Notify dst clients the records from src are added
		for (size_t i = 0; i < new_array->size; i++)
			aspa_table_notify_clients(src, &(new_array->data[i]), rtr_socket, true);

	return res;
}

static void *binsearch(const uint32_t key, uint32_t *array, size_t nmemb)
{
	size_t mid, top;
	int val;
	uint32_t *piv, *base = array;

	mid = top = nmemb;

	while (mid) {
		mid = top / 2;

		piv = base + mid;

		val = key - *piv;


		if (val == 0) {
			return piv;
		}
		if (val >= 0) {
			base = piv;
		}
		top -= mid;
	}
	return NULL;
}

enum aspa_hop_result aspa_path_hop(struct aspa_table *aspa_table, uint32_t customer_asn, uint32_t provider_asn)
{
	pthread_rwlock_rdlock(&aspa_table->lock);

	struct aspa_store_node *node = aspa_table->store;

	bool customer_found = 0;

	while (node != NULL) {
		struct aspa_array *aspa_array = node->aspa_array;

		int pos = aspa_array_search(aspa_array, customer_asn);

		if (pos == -1)
			goto cont;


		customer_found = 1;

		struct aspa_record *record = &aspa_array->data[pos];

		for (int i = 0; i < ASPA_RECORD_CACHE_SIZE; i++) {
			if (record->provider_asns_prio[i] == provider_asn)
				return ASPA_PROVIDER_PLUS;
		}

		uint32_t* prov = binsearch(provider_asn, record->provider_asns, record->provider_count);

		if (prov != NULL) {
			for (int i = ASPA_RECORD_CACHE_SIZE-1; i > 0; i--) {
				record->provider_asns_prio[i] = record->provider_asns_prio[i-1];
			}
			record->provider_asns_prio[0] = *prov;
			pthread_rwlock_unlock(&aspa_table->lock);
			return ASPA_PROVIDER_PLUS;
		}

		cont:
			node = node->next;
	}

	pthread_rwlock_unlock(&aspa_table->lock);
	return customer_found ? ASPA_NOT_PROVIDER_PLUS : ASPA_NO_ATTESTATION;
}

RTRLIB_EXPORT enum aspa_verification_result aspa_verify_path_downstream_alt(struct aspa_table *aspa_table, uint32_t *as_sequence, size_t len)
{
	if (len < 1)
		return AS_PATH_INVALID;
	if (len == 1)
		return AS_PATH_VALID;

	bool found_no_attestation = 0;

	for (size_t i = 1; i < len; i++) {
		switch(aspa_path_hop(aspa_table, as_sequence[i-1], as_sequence[i])) {
		case ASPA_NOT_PROVIDER_PLUS:
			return AS_PATH_INVALID;
		case ASPA_NO_ATTESTATION:
			found_no_attestation = 1;
		default: break;
		}
	}

	return found_no_attestation ? AS_PATH_UNKNOWN : AS_PATH_VALID;
}

RTRLIB_EXPORT enum aspa_verification_result aspa_verify_path(struct aspa_table *aspa_table, uint32_t *as_sequence, size_t len, enum aspa_direction direction)
{
	// Optimized AS_PATH verification algorithm using zero based array
	// where the origin AS has index N - 1 and the latest AS in the AS_PATH
	// has index 0.
	// Doesn't check any hop twice.
	if (len < 1)
		return AS_PATH_INVALID;
	if (len == 1)
		return AS_PATH_VALID;
	if (len == 2 && direction == ASPA_DOWNSTREAM)
		return AS_PATH_VALID;

	size_t r = len - 1;
	enum aspa_hop_result last_hop_right;
	while (r > 0 &&
		(last_hop_right = aspa_path_hop(aspa_table, as_sequence[r], as_sequence[r - 1])) == ASPA_PROVIDER_PLUS)
		r -= 1;
	
	if (direction == ASPA_UPSTREAM && r == 0)
		return AS_PATH_VALID;

	bool found_nP_from_right = false;
	bool found_nP_from_left = false;

	size_t l = 0;
	enum aspa_hop_result last_hop_left;
	if (direction == ASPA_DOWNSTREAM) {
		while (l < r &&
			(last_hop_left = aspa_path_hop(aspa_table, as_sequence[l], as_sequence[l + 1])) == ASPA_PROVIDER_PLUS)
			l += 1;
		assert(l <= r);
		if (r - l <= 1)
			return AS_PATH_VALID;
	}

	size_t rr = r - 1;

	if (last_hop_right == ASPA_NOT_PROVIDER_PLUS) {
		found_nP_from_right = true;
	} else while (rr > l + 1) {
		size_t c = rr;
		rr -= 1;
		if (aspa_path_hop(aspa_table, as_sequence[c], as_sequence[rr]) == ASPA_NOT_PROVIDER_PLUS) {
			found_nP_from_right = true;
			break;
		}
	}

	if (direction == ASPA_DOWNSTREAM && found_nP_from_right) {
		size_t ll = l + 1;

		if (last_hop_left == ASPA_NOT_PROVIDER_PLUS) {
			found_nP_from_left = true;
		} else while (ll < rr) {
			size_t c = ll;
			ll += 1;
			if (aspa_path_hop(aspa_table, as_sequence[c], as_sequence[ll]) == ASPA_NOT_PROVIDER_PLUS) {
				found_nP_from_left = true;
				break;
			}
		}
	}

	if (direction == ASPA_DOWNSTREAM && found_nP_from_left && found_nP_from_left)
		return AS_PATH_INVALID;

	if (direction == ASPA_UPSTREAM && found_nP_from_left)
		return AS_PATH_INVALID;
	
	return AS_PATH_UNKNOWN;
}

// implements 6.2.2. "Formal Procedure for Verification of Downstream Paths" of aspa verification draft
RTRLIB_EXPORT enum aspa_verification_result aspa_verify_downstream_alt(struct aspa_table *aspa_table, uint32_t *as_sequence, size_t len)
{
	// zero length as_paths are invalid (design choice)
	if (len < 1)
		return AS_PATH_INVALID;

	// as_paths of length 1 or 2 are always valid
	if (len <= 2)
		return AS_PATH_VALID;

	// find the lowest value 1 <= u < as_path_length
	//     for which as_path[u-1] is not customer of as_path[u]
	//     i.e. u_min marks the upper end of the lowest not-customer-of-hop
	size_t u_min = len;
	for (size_t u = 1; u < len; u++) {
		if (aspa_path_hop(aspa_table, as_sequence[u-1], as_sequence[u]) == ASPA_NOT_PROVIDER_PLUS) {
			u_min = u;
			break;
		}
	}

	// find the highest value 1 <= v < as_path_length
	//     for which as_path[v-1] is not provider of as_path[v]
	//     i.e. v_max marks the upper end of the lowest not-provider-of-hop
	size_t v_max = 0;
	for (size_t v = len - 1; v >= 1; v--) {
		if (aspa_path_hop(aspa_table, as_sequence[v], as_sequence[v-1]) == ASPA_NOT_PROVIDER_PLUS) {
			v_max = v;
			break;
		}
	}

	// u_min == v_max if there's only 1 hop where neither is the other's provider
	// u_min > v_max if for each hop, one is the other's provider
	// if there is more than 1 hop with NOT_PROVIDER, as_path is invalid
	if (u_min < v_max)
		return AS_PATH_INVALID;


	// find up-ramp (streak of upstream providerships):
	//     smallest K such that for all 1 <= i <= K,
	//     the hop i -> i+1 is customer -> provider
	size_t K = 0;
	for (size_t i = 1; i < len; i++) {
		if (aspa_path_hop(aspa_table, as_sequence[i-1], as_sequence[i]) == ASPA_PROVIDER_PLUS)
			K++;
		else
			break;
	}

	// find down-ramp (streak of downstream providerships):
	//     smallest L such that for all N-2 >= j >= L,
	//     the hop j -> j+1 is provider -> customer
	size_t L = len - 1;
	for (size_t j = len - 2; j >= 0; j--) {
		if (aspa_path_hop(aspa_table, as_sequence[j+1], as_sequence[j]) == ASPA_PROVIDER_PLUS)
			L--;
		else
			break;
	}

	// the providership-streaks up-ramp and down-ramp may have
	//    max. one [AS_NO_ATTESTATION, AS_NOT_PROVIDER] hop inbetween
	//    (overlap allowed)
	if (K + 1 >= L)
		return AS_PATH_VALID;

	// there were too many AS_NO_ATTESTATION along the as_path
	return AS_PATH_UNKNOWN;
}
