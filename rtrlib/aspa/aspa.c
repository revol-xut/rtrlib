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
#include "aspa_store/aspa_store.h"

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

static int cmp_uint32_t(const void *a, const void *b) {
	return ( *(uint32_t*)a - *(uint32_t*)b );
}

RTRLIB_EXPORT int aspa_table_add(struct aspa_table *aspa_table,
				struct aspa_record *record, struct rtr_socket *rtr_socket,
				bool overwrite)
{
	if (!aspa_table)
		return ASPA_ERROR;

	pthread_rwlock_wrlock(&aspa_table->lock);

	struct aspa_array *array;

	// sort to-be-added providers in ascending order
	qsort(record->provider_asns, record->provider_count,
			sizeof(uint32_t), cmp_uint32_t);

	// Find the socket's corresponding aspa_array.
	// If fast lookup suceeds (rtr_socket->aspa_table == aspa_table),
	// access rtr_socket->aspa_array directly,
	// perform lookup on aspa_table->store insted.

	// Use fast lookup
	if (rtr_socket->aspa_table == aspa_table) {
		// Check if an ASPA array exists for this socket
		if (rtr_socket->aspa_array == NULL) {
			// Create a new ASPA array, store that array alongside with the socket in the table
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
	if (aspa_array_insert(array, *record) < 0) { //TODO: check if we want to overwrite here
		pthread_rwlock_unlock(&aspa_table->lock);
		return ASPA_ERROR;
	}

	pthread_rwlock_unlock(&aspa_table->lock);

	// Notify clients that the record has been added
	aspa_table_notify_clients(aspa_table, record, rtr_socket, true);

	return ASPA_SUCCESS;
}

RTRLIB_EXPORT int aspa_table_remove(struct aspa_table *aspa_table,
					struct aspa_record *record,
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

	struct aspa_record *aspa_record = aspa_array_search(array, record->customer_asn);

	if (aspa_record == NULL) { // error occured
		pthread_rwlock_unlock(&aspa_table->lock);
		return ASPA_RECORD_NOT_FOUND;
	}

	// Remove record aspa_array
	if (aspa_array_free_entry(array, aspa_record) < 0) {
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

static void *binsearch(const uint32_t key, uint32_t *array, size_t n)
{
       size_t mid, top;
       int val;
       uint32_t *piv, *base = array;

       mid = top = n;

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

enum aspa_hop_result aspa_check_hop(struct aspa_table *aspa_table, uint32_t customer_asn, uint32_t provider_asn)
{
	pthread_rwlock_rdlock(&aspa_table->lock);

	bool customer_found = false;
	
	for (struct aspa_store_node *node = aspa_table->store; node != NULL;
				node = node->next) {

		struct aspa_record *aspa_record = aspa_array_search(node->aspa_array,
				customer_asn);

		if (aspa_record == NULL)
			continue;
			
		customer_found = true;

		uint32_t* provider = binsearch(provider_asn, aspa_record->provider_asns,
				aspa_record->provider_count);

		if (provider != NULL) {
			pthread_rwlock_unlock(&aspa_table->lock);
			return ASPA_PROVIDER_PLUS;
		}
	}

	pthread_rwlock_unlock(&aspa_table->lock);
	return customer_found ? ASPA_NOT_PROVIDER_PLUS : ASPA_NO_ATTESTATION;
}

static enum aspa_verification_result aspa_verify_upstream(struct aspa_table *aspa_table, uint32_t as_path[], size_t len)
{
	if (len < 1)
		return ASPA_AS_PATH_INVALID;
	if (len == 1)
		return ASPA_AS_PATH_VALID;

	bool has_unattested_hop = false;

	for (size_t i = 1; i < len; i++) {
		switch (aspa_check_hop(aspa_table, as_path[i - 1], as_path[i])) {
		case ASPA_NO_ATTESTATION:
			has_unattested_hop = true;
			break;
		case ASPA_NOT_PROVIDER_PLUS:
			return ASPA_AS_PATH_INVALID;
		case ASPA_PROVIDER_PLUS:
			break;
		}
	}

	return has_unattested_hop ? ASPA_AS_PATH_UNKNOWN : ASPA_AS_PATH_VALID;
}

/**
 * @brief Implements 6.2.2. "Formal Procedure for Verification of Downstream Paths" of aspa verification draft
 */
static enum aspa_verification_result aspa_verify_downstream(struct aspa_table *aspa_table, uint32_t as_path[], size_t len)
{
	// zero length as_paths are invalid
	if (len < 1)
		return ASPA_AS_PATH_INVALID;

	// AS_PATH of length 1 or 2 are always valid
	if (len <= 2)
		return ASPA_AS_PATH_VALID;

	// Find the lowest value 1 <= u < len such that AS_PATH[u] is not provider of AS_PATH[u-1].
	// u_min marks the first AS breaking the customer-provider relationship chain.
	size_t u_min = len;
	for (size_t u = 1; u < len; u++) {
		if (aspa_check_hop(aspa_table, as_path[u-1], as_path[u]) == ASPA_NOT_PROVIDER_PLUS) {
			u_min = u;
			break;
		}
	}

	// Find the highest value 1 <= v < len such that AS_PATH[v-1] is not provider of AS_PATH[v].
	// v_max marks the first AS breaking the customer-provider relationship chain.
	size_t v_max = 0;
	for (size_t v = len - 1; v >= 1; v--) {
		if (aspa_check_hop(aspa_table, as_path[v], as_path[v-1]) == ASPA_NOT_PROVIDER_PLUS) {
			v_max = v;
			break;
		}
	}

	// u_min == v_max if there's only a single hop where neither one is the other's provider
	// u_min > v_max if each AS along the path is the other's provider
	// if there is more than an single hop with nP, AS_PATH is invalid
	if (u_min < v_max)
		return ASPA_AS_PATH_INVALID;

	// Find up-ramp:
	// smallest K such that for all 1 <= i <= K,
	// the AS_PATH[i+1] is a provider of AS_PATH[i]
	size_t K = 0;
	for (size_t i = 1; i < len; i++) {
		if (aspa_check_hop(aspa_table, as_path[i - 1], as_path[i]) == ASPA_PROVIDER_PLUS)
			K++;
		else
			break;
	}

	// Find down-ramp:
	// smallest L such that for all N-2 >= j >= L,
	// AS_PATH[j] is a provider of AS_PATH[j+1]
	// TODO: will not work because size_t is unsigned!!
	size_t L = len - 1;
	for (size_t j = len - 2; j >= 0; j--) {
		if (aspa_check_hop(aspa_table, as_path[j + 1], as_path[j]) == ASPA_PROVIDER_PLUS)
			L--;
		else
			break;
	}

	// there's only a single unattested (nA) or not-provider (nP) hops allowed between the up and down ramp.
	if (K + 1 >= L)
		return ASPA_AS_PATH_VALID;

	// too many unattested (nA) or not-provider (nP) hops in the AS_PATH
	return ASPA_AS_PATH_UNKNOWN;
}

RTRLIB_EXPORT enum aspa_verification_result aspa_verify_as_path(struct aspa_table *aspa_table, enum aspa_direction direction, uint32_t as_path[], size_t len)
{
	switch (direction) {
		case ASPA_UPSTREAM:
			return aspa_verify_upstream(aspa_table, as_path, len);
		case ASPA_DOWNSTREAM:
			return aspa_verify_downstream(aspa_table, as_path, len);
	}
	
	return ASPA_AS_PATH_UNKNOWN;
}


RTRLIB_EXPORT size_t aspa_collapse_as_path(uint32_t as_path[], size_t len)
{
	if (len == 0)
		return 0;

	size_t i = 1;

	while (i < len && as_path[i-1] != as_path[i])
		i++;

	if (i == len)
		return len;

	size_t j = i;

	i++;

	while (true) { // equivalent to while (i < len)
		while (i < len && as_path[i-1] == as_path[i])
			i++;

		if (i == len)
			break;

		as_path[j++] = as_path[i++];
	}

	return j;
}
