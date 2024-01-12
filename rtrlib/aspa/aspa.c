/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#include "rtrlib/aspa/aspa_array/aspa_array.h"
#include "rtrlib/aspa/aspa_private.h"
#include "rtrlib/lib/alloc_utils_private.h"
#include "rtrlib/rtrlib_export_private.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

static enum aspa_status aspa_table_notify_clients(struct aspa_table *aspa_table, struct aspa_record *record,
						  const struct rtr_socket *rtr_socket,
						  const enum aspa_operation_type operation_type)
{
	if (!aspa_table || !rtr_socket)
		return ASPA_ERROR;

	if (aspa_table->update_fp && record) {
		// Realloc in order not to expose internal record
		struct aspa_record rec = *record;
		size_t size = sizeof(uint32_t) * record->provider_count;
		rec.provider_asns = lrtr_malloc(size);
		if (record->provider_asns && size > 0)
			memcpy(rec.provider_asns, record->provider_asns, size);
		else
			rec.provider_asns = NULL;

		aspa_table->update_fp(aspa_table, rec, rtr_socket, operation_type);
	}

	return ASPA_SUCCESS;
}

static enum aspa_status aspa_store_insert_node(struct aspa_store_node **store, struct rtr_socket *rtr_socket,
					       struct aspa_array *aspa_array, struct aspa_store_node ***new_node)
{
	// Allocate new node
	struct aspa_store_node *new = lrtr_malloc(sizeof(struct aspa_store_node));

	if (new == NULL)
		return ASPA_ERROR;

	// Store socket and ASPA array
	new->rtr_socket = rtr_socket;
	new->aspa_array = aspa_array;

	// prepend new node
	new->next = *store; // may be NULL
	*store = new;

	if (new_node)
		*new_node = store;

	return ASPA_SUCCESS;
}

static void aspa_store_remove_node(struct aspa_store_node **node)
{
	struct aspa_store_node *tmp = *node;
	*node = (*node)->next;
	lrtr_free(tmp);
}

static struct aspa_store_node **aspa_store_get_node(struct aspa_store_node **node, const struct rtr_socket *rtr_socket)
{
	if (node == NULL || *node == NULL || rtr_socket == NULL)
		return NULL;

	//	struct aspa_store_node *node = *head;

	while (*node != NULL) {
		if ((*node)->rtr_socket == rtr_socket) {
			return node;
		}
		node = &(*node)->next;
	}

	return NULL;
}

RTRLIB_EXPORT void aspa_table_init(struct aspa_table *aspa_table, aspa_update_fp update_fp)
{
	aspa_table->update_fp = update_fp;
	aspa_table->store = NULL;
	pthread_rwlock_init(&(aspa_table->lock), NULL);
}

static enum aspa_status aspa_table_remove_node(struct aspa_table *aspa_table, struct aspa_store_node **node,
					       bool notify)
{
	if (!node)
		return ASPA_ERROR;

	if (!*node)
		// Doesn't exist anymore
		return ASPA_SUCCESS;

	struct aspa_array *array = (*node)->aspa_array;
	struct rtr_socket *socket = (*node)->rtr_socket;

	if (!array)
		// Doesn't exist anymore
		return ASPA_SUCCESS;

	// Notify clients about these records being removed
	if (notify) {
		for (size_t i = 0; i < array->size; i++) {
			aspa_table_notify_clients(aspa_table, aspa_array_get_record(array, i), socket, false);
		}
	}

	// Remove node for socket
	aspa_store_remove_node(node);

	// Release all records and their provider sets
	aspa_array_free(array, true);

	return ASPA_SUCCESS;
}

RTRLIB_EXPORT enum aspa_status aspa_table_src_remove(struct aspa_table *aspa_table, struct rtr_socket *rtr_socket,
						     bool notify)
{
	pthread_rwlock_wrlock(&aspa_table->lock);

	struct aspa_store_node **node = aspa_store_get_node(&aspa_table->store, rtr_socket);

	if (!node || !*node) {
		// Already gone
		pthread_rwlock_unlock(&(aspa_table->lock));
		return ASPA_SUCCESS;
	}

	return aspa_table_remove_node(aspa_table, node, notify);
}

RTRLIB_EXPORT void aspa_table_free(struct aspa_table *aspa_table, bool notify)
{
	// To destroy the lock, first acquire the lock
	pthread_rwlock_wrlock(&aspa_table->lock);

	// Free store
	while (aspa_table->store != NULL) {
		aspa_table_remove_node(aspa_table, &aspa_table->store, notify);
	}

	aspa_table->store = NULL;

	pthread_rwlock_unlock(&aspa_table->lock);
	pthread_rwlock_destroy(&aspa_table->lock);
}

// MARK: - ASPA table update functions

static int compare_update_operations(const void *a, const void *b)
{
	const struct aspa_update_operation *op1 = a;
	const struct aspa_update_operation *op2 = b;

	// compare index in case customer ASNs match, so result is stable
	if (op1->record.customer_asn < op2->record.customer_asn)
		return -1;
	else if (op1->record.customer_asn > op2->record.customer_asn)
		return 1;
	else if (op1->index > op2->index)
		return 1;
	else if (op1->index < op2->index)
		return -1;
	else
		return 0;
}

static int compare_asns(const void *a, const void *b)
{
	return *(uint32_t *)a - *(uint32_t *)b;
}

// MARK: - Swap-In Update Mechanism

static enum aspa_status aspa_table_compute_update_internal(struct rtr_socket *rtr_socket, struct aspa_array *array,
							   struct aspa_array *new_array,
							   struct aspa_update_operation *operations, size_t count,
							   struct aspa_update_operation **failed_operation)
{
	if (!rtr_socket || !operations || count == 0 || !failed_operation)
		return ASPA_ERROR;

	size_t existing_i = 0;

	for (size_t i = 0; i < count; i++) {
		struct aspa_update_operation *current = &operations[i];
		struct aspa_update_operation *next = (i < count - 1) ? &(operations[i + 1]) : NULL;

		// Sort providers
		if (current->record.provider_count > 0 && current->record.provider_asns)
			qsort(current->record.provider_asns, current->record.provider_count, sizeof(uint32_t),
			      compare_asns);

		while (existing_i < array->size) {
			struct aspa_record *existing_record = aspa_array_get_record(array, existing_i);

			// Skip over records untouched by these add/remove operations
			if (existing_record->customer_asn < current->record.customer_asn) {
				existing_i++;

				if (aspa_array_append(new_array, existing_record) != ASPA_SUCCESS) {
					*failed_operation = current;
					return ASPA_ERROR;
				}
			} else {
				break;
			}
		}

		struct aspa_record *existing_record = aspa_array_get_record(array, existing_i);

		// existing record and current op have matching CAS
		bool existing_matches_current = existing_record &&
						existing_record->customer_asn == current->record.customer_asn;

		// next record and current op have matching CAS
		bool next_matches_current = next && next->record.customer_asn == current->record.customer_asn;

		// MARK: Handling 'add' operations
		if (current->type == ASPA_ADD) {
			// Attempt to add record with $CAS, but record with $CAS already exists
			// Error: Duplicate Add.
			if (existing_matches_current) {
				*failed_operation = current;
				return ASPA_DUPLICATE_RECORD;
			}

			// Attempt to add record with $CAS twice.
			// Error: Duplicate Add.
			if (next_matches_current && next->type == ASPA_ADD) {
				*failed_operation = next;
				return ASPA_DUPLICATE_RECORD;
			}

			// This operation adds a record with $CAS, the next op however removes this $CAS record again.
			// Also, verify that the record doesn't already exist.
			if (next_matches_current && next->type == ASPA_REMOVE) {
				// Mark these operations as skipped
				// (clients don't get notified about these updates)
				current->skip = true;
				next->skip = true;

				// Skip the next op because it's annihilated by the current operation.
				i += 1;
				continue;
			}

			// Add record by appending it to new array
			if (aspa_array_append(new_array, &current->record) != ASPA_SUCCESS) {
				*failed_operation = current;
				return ASPA_ERROR;
			}
		}

		// MARK: Handling 'remove' operations
		else if (current->type == ASPA_REMOVE) {
			// Initially, there must not be a provider array associated
			// with a 'remove' operation. We manually associate the existing
			// record's provider array with this 'remove' operation to
			// a, notify clients later because we use the operation array as the diff and
			// b, release provider arrays of removed records if the update gets applied
			assert(current->record.provider_count == 0);
			assert(current->record.provider_asns == NULL);

			// Attempt to remove record with $CAS, but record with $CAS does not exist
			// Error: Removal of unknown record.
			if (!existing_matches_current) {
				*failed_operation = current;
				return ASPA_RECORD_NOT_FOUND;
			}

			// Attempt to remove record with $CAS twice.
			// Error: Removal of unknown record.
			if (next_matches_current && next->type == ASPA_REMOVE) {
				*failed_operation = next;
				return ASPA_RECORD_NOT_FOUND;
			}

			// "Remove" record by simply not appending it to the new array
			existing_i += 1;

			current->record.provider_count = existing_record->provider_count;
			current->record.provider_asns = existing_record->provider_asns;
		}
	}

	// Copy remaining data into new new_array
	if (existing_i < array->size) {
		aspa_array_append_contents(new_array, aspa_array_get_record(array, existing_i),
					   array->size - existing_i);
	}

	return ASPA_SUCCESS;
}

enum aspa_status aspa_table_compute_update(struct aspa_table *aspa_table, struct rtr_socket *rtr_socket,
					   struct aspa_update_operation *operations, size_t count,
					   struct aspa_update_operation **failed_operation, struct aspa_update **update)
{
	if (!rtr_socket || !operations || count == 0 || !failed_operation || !update)
		return ASPA_ERROR;

	if (!*update) {
		*update = lrtr_malloc(sizeof(struct aspa_update));

		if (!*update) {
			return ASPA_ERROR;
		}
	}

	// stable sort operations, so operations dealing with the same customer ASN
	// are located right next to each other
	qsort(operations, count, sizeof(struct aspa_update_operation), compare_update_operations);

	// MARK: Lock table while retrieving array for socket
	pthread_rwlock_wrlock(&aspa_table->lock);

	struct aspa_store_node **node = aspa_store_get_node(&aspa_table->store, rtr_socket);

	if (!node || !*node) {
		struct aspa_array *array;
		if (aspa_array_create(&array) != ASPA_SUCCESS || !array ||
		    aspa_store_insert_node(&aspa_table->store, rtr_socket, array, &node) != ASPA_SUCCESS) {
			pthread_rwlock_unlock(&aspa_table->lock);
			return ASPA_ERROR;
		}
	}

	if (!node || !*node || !(*node)->aspa_array) {
		pthread_rwlock_unlock(&aspa_table->lock);
		return ASPA_ERROR;
	}

	pthread_rwlock_unlock(&aspa_table->lock);

	(*update)->table = aspa_table;
	(*update)->node = *node;
	(*update)->old_array = NULL;
	(*update)->operations = operations;
	(*update)->operation_count = count;
	(*update)->is_applied = false;

	struct aspa_array *new_array = NULL;
	if (aspa_array_create(&new_array) != ASPA_SUCCESS) {
		// We don't need to free the update we may have allocated previously
		// as this must by done by the calling `aspa_table_update_cleanup`
		return ASPA_ERROR;
	}

	// Enforce read lock
	pthread_rwlock_rdlock(&aspa_table->lock);
	enum aspa_status res = aspa_table_compute_update_internal(rtr_socket, (*node)->aspa_array, new_array,
								  operations, count, failed_operation);
	pthread_rwlock_unlock(&aspa_table->lock);

	if (res == ASPA_SUCCESS) {
		(*update)->node = *node;
		(*update)->new_array = new_array;
	} else {
		(*update)->table = NULL;
		(*update)->node = NULL;
		(*update)->new_array = NULL;

		// Update computation failed so release newly created array.
		// Note, we must not release associated provider arrays here.
		aspa_array_free(new_array, false);
	}

	return res;
}

void aspa_table_apply_update(struct aspa_update *update)
{
	if (!update || !update->table || !update->operations || !update->node || !update->new_array ||
	    update->is_applied)
		return;

	pthread_rwlock_wrlock(&update->table->lock);
	update->old_array = update->node->aspa_array;
	update->node->aspa_array = update->new_array;
	pthread_rwlock_unlock(&update->table->lock);

	struct rtr_socket *socket = update->node->rtr_socket;
	struct aspa_table *table = update->table;

	// Prevent further access and attempts to re-apply update
	update->new_array = NULL;
	update->node = NULL;
	update->table = NULL;
	update->is_applied = true;

	// Notify clients
	for (size_t i = 0; i < update->operation_count; i++) {
		struct aspa_update_operation *op = &update->operations[i];

		// Notify clients if the operation hasn't skipped
		// We can directly use the operation array as the source for the diff
		// so we don't need to rely on first notifying clients about all records
		// in the old_array being removed and then every record in the new_array
		// being added again.
		if (!op->skip)
			aspa_table_notify_clients(table, &op->record, socket, op->type);
	}
}

void aspa_table_update_cleanup(struct aspa_update *update)
{
	if (!update)
		return;

	if (update->old_array) {
		// We don't need to release provider arrays as this is done below.
		aspa_array_free(update->old_array, false);
		update->old_array = NULL;
	}

	if (update->operations) {
		// Update got applied, so release provider arrays of
		// - records that were removed (reference stored inside the corresponding operation)
		// - records in skipped 'add' operations that weren't added to the table
		if (update->is_applied) {
			for (size_t i = 0; i < update->operation_count; i++) {
				struct aspa_update_operation *op = &update->operations[i];

				// Skipped records aren't added to the table, so their provider arrays
				// must be released.
				bool can_free_providers = op->type == ASPA_REMOVE || (op->skip && op->type == ASPA_ADD);

				if (can_free_providers && op->record.provider_asns) {
					lrtr_free(op->record.provider_asns);
					op->record.provider_asns = NULL;
				}
			}
		}

		// Update wasn't applied, so release provider arrays of
		// - every record in an 'add' operation
		else {
			for (size_t i = 0; i < update->operation_count; i++) {
				struct aspa_update_operation *op = &update->operations[i];

				if (op->type == ASPA_ADD && op->record.provider_asns) {
					lrtr_free(op->record.provider_asns);
					op->record.provider_asns = NULL;
				}
			}
		}

		lrtr_free(update->operations);
		update->operations = NULL;
	}

	lrtr_free(update);
}

enum aspa_status aspa_table_src_replace(struct aspa_table *dst, struct aspa_table *src, struct rtr_socket *rtr_socket,
					bool notify_dst, bool notify_src)
{
	if (dst == NULL || src == NULL || rtr_socket == NULL || src == dst)
		return ASPA_ERROR;

	pthread_rwlock_wrlock(&dst->lock);
	pthread_rwlock_wrlock(&src->lock);

	struct aspa_store_node **src_node = aspa_store_get_node(&src->store, rtr_socket);

	if (!src_node || !*src_node || !(*src_node)->aspa_array) {
		pthread_rwlock_unlock(&src->lock);
		pthread_rwlock_unlock(&dst->lock);
		return ASPA_ERROR;
	}

	struct aspa_array *new_array = (*src_node)->aspa_array;

	struct aspa_store_node **existing_node = aspa_store_get_node(&dst->store, rtr_socket);
	struct aspa_array *old_array = NULL;

	if (!existing_node || !*existing_node) {
		aspa_store_insert_node(&dst->store, rtr_socket, new_array, NULL);
	} else if (!*existing_node) {
		pthread_rwlock_unlock(&src->lock);
		pthread_rwlock_unlock(&dst->lock);
		return ASPA_ERROR;
	} else {
		old_array = (*existing_node)->aspa_array;

		// Swap in new array
		(*existing_node)->aspa_array = new_array;
	}

	// Remove socket from source table's store
	aspa_store_remove_node(src_node);

	pthread_rwlock_unlock(&src->lock);
	pthread_rwlock_unlock(&dst->lock);

	if (notify_src)
		// Notify src clients their records are being removed
		for (size_t i = 0; i < new_array->size; i++)
			aspa_table_notify_clients(src, aspa_array_get_record(new_array, i), rtr_socket, ASPA_REMOVE);

	if (old_array) {
		if (notify_dst)
			// Notify dst clients of their existing records are being removed
			for (size_t i = 0; i < old_array->size; i++)
				aspa_table_notify_clients(dst, aspa_array_get_record(old_array, i), rtr_socket,
							  ASPA_REMOVE);

		// Free the old array and their provider sets
		aspa_array_free(old_array, true);
	}

	if (notify_dst)
		// Notify dst clients the records from src are added
		for (size_t i = 0; i < new_array->size; i++)
			aspa_table_notify_clients(dst, aspa_array_get_record(new_array, i), rtr_socket, ASPA_ADD);

	return ASPA_SUCCESS;
}
