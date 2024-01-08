/*
* This file is part of RTRlib.
*
* This file is subject to the terms and conditions of the MIT license.
* See the file LICENSE in the top level directory for more details.
*
* Website; http://rtrlib.realmv6.org/
*/

#include "rtrlib/lib/alloc_utils_private.h"
#include "rtrlib/aspa/aspa_private.h"
#include "rtrlib/aspa/aspa_array/aspa_array.h"

#include <string.h>
#include <assert.h>

static struct aspa_record *create_aspa_record(uint32_t cas, uint32_t *provider_asns, size_t provider_count)
{
	struct aspa_record *aspa_record = lrtr_malloc(sizeof(struct aspa_record));
	aspa_record->customer_asn = cas;

	size_t size = provider_count * sizeof(uint32_t);
	aspa_record->provider_asns = lrtr_malloc(size);
	memcpy(aspa_record->provider_asns, provider_asns, size);

	aspa_record->provider_count = provider_count;

	return aspa_record;
}

static enum aspa_status aspa_store_insert_node(struct aspa_store_node **store, struct rtr_socket *rtr_socket,
					       struct aspa_array *aspa_array)
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

	return ASPA_SUCCESS;
}

static int compare_records(const void *a, const void *b)
{
	return (*(struct aspa_record **)a)->customer_asn - (*(struct aspa_record **)b)->customer_asn;
}

static void insert_new_socket_records(struct aspa_table *aspa_table,
		struct aspa_record **records, size_t record_count)
{
	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;

	struct aspa_array *array = NULL;
	assert(aspa_array_create(&array) == ASPA_SUCCESS);
	assert(array);

	assert(aspa_store_insert_node(&aspa_table->store, rtr_socket, array) == ASPA_SUCCESS);

	qsort(records, record_count, sizeof(*records), compare_records);

	for (size_t i = 0; i < record_count; i++) {
		aspa_array_insert(array, i, records[i]);
		printf("%zu: %u\n", i, records[i]->customer_asn);
	}
}

static struct aspa_table *test_create_aspa_table()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);


	size_t i = 0;
	struct aspa_record *records[17];

	// { 302, 402, 502, 500, 400, 300 }, 6, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);
	// { 301, 401, 501, 502, 502, 402, 302 }, 7, ASPA_DOWNSTREAM) == ASPA_AS_PATH_INVALID);
	// { 302, 402, 502, 500, 400, 300 }, 6, ASPA_DOWNSTREAM) == ASPA_AS_PATH_UNKNOWN);
	records[i++] = create_aspa_record(100, (uint32_t []){ 200, 201 }, 2);
	records[i++] = create_aspa_record(200, (uint32_t []){ 300 }, 1);
	records[i++] = create_aspa_record(300, (uint32_t []){ 400 }, 1);
	records[i++] = create_aspa_record(400, (uint32_t []){ 500 }, 1);

	records[i++] = create_aspa_record(501, (uint32_t []){ 601 }, 1);
	records[i++] = create_aspa_record(401, (uint32_t []){ 501 }, 1);
	records[i++] = create_aspa_record(301, (uint32_t []){ 401 }, 1);
	records[i++] = create_aspa_record(201, (uint32_t []){ 301 }, 1);

	records[i++] = create_aspa_record(502, (uint32_t []){ 602 }, 1);
	records[i++] = create_aspa_record(402, (uint32_t []){ 502 }, 1);
	records[i++] = create_aspa_record(302, (uint32_t []){ 402 }, 1);
	records[i++] = create_aspa_record(202, (uint32_t []){ 302 }, 1);

	// 103 --> 203 <--> 303 <--> 403 <-- 304
	records[i++] = create_aspa_record(103, (uint32_t []){ 203 }, 1);
	records[i++] = create_aspa_record(203, (uint32_t []){ 303 }, 1);
	records[i++] = create_aspa_record(303, (uint32_t []){ 203, 403 }, 2);
	records[i++] = create_aspa_record(403, (uint32_t []){ 303 }, 1);
	records[i++] = create_aspa_record(304, (uint32_t []){ 403 }, 1);

	insert_new_socket_records(aspa_table, records, 17);


	struct aspa_record *records_2[1] = {
		create_aspa_record(100, (uint32_t []){ 200, 202 }, 2)
	};
	insert_new_socket_records(aspa_table, records_2, 1);

	return aspa_table;
}

static void test_hopping(struct aspa_table* aspa_table) {
    // check that provider and not provider holds
	assert(aspa_check_hop(aspa_table, 100, 200) == ASPA_PROVIDER_PLUS);
	assert(aspa_check_hop(aspa_table, 200, 100) == ASPA_NOT_PROVIDER_PLUS);

	assert(aspa_check_hop(aspa_table, 200, 300) == ASPA_PROVIDER_PLUS);
	assert(aspa_check_hop(aspa_table, 500, 999) == ASPA_NO_ATTESTATION);

	assert(aspa_check_hop(aspa_table, 999, 999) == ASPA_NO_ATTESTATION);

	// multiple dissimilar aspas
	assert(aspa_check_hop(aspa_table, 100, 201) == ASPA_PROVIDER_PLUS);
	assert(aspa_check_hop(aspa_table, 100, 202) == ASPA_PROVIDER_PLUS);
}

// test multiple routes
// - upstream (only customer-provider-hops)
//   - one not provider and one not attested: invalid
//   - one not attested: unknown
//   - all attested: valid

static void test_upstream(struct aspa_table* aspa_table) {
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ }, 0, ASPA_UPSTREAM) == ASPA_AS_PATH_VALID);
	// TODO ^ this was invalid before

	// paths of length 1 are valid
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 100 }, 1, ASPA_UPSTREAM) == ASPA_AS_PATH_VALID);

	// valid upstream paths
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 200, 100 }, 2, ASPA_UPSTREAM) == ASPA_AS_PATH_VALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 300, 200 }, 2, ASPA_UPSTREAM) == ASPA_AS_PATH_VALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 300, 200, 100 }, 3, ASPA_UPSTREAM) == ASPA_AS_PATH_VALID);

	// single not-provider hop (nP)

	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 999, 100 }, 2, ASPA_UPSTREAM) == ASPA_AS_PATH_INVALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 300, 999, 100 }, 3, ASPA_UPSTREAM) == ASPA_AS_PATH_INVALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 999, 999, 100 }, 3, ASPA_UPSTREAM) == ASPA_AS_PATH_INVALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 999, 100, 999 }, 3, ASPA_UPSTREAM) == ASPA_AS_PATH_INVALID);

	// single unattested hop (nA)
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 999, 500, 400, 300 }, 4, ASPA_UPSTREAM) == ASPA_AS_PATH_UNKNOWN);
}

static void test_downstream(struct aspa_table* aspa_table) {
	// paths of length 1 <= N <= 2 are valid
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 999 }, 1, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 998, 999 }, 2, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);

	// either up- or down-ramp is valid, not both
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 300, 400, 500 }, 3, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 500, 400, 300 }, 3, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);

	// w/o customer-provider gap
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 300, 400, 500, 400, 300 }, 5, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);

	// single not-provider (nP) in between
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 302, 402, 502, 500, 400, 300 }, 6, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);

	// two highest-level hops are nP
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 301, 401, 501, 502, 502, 402, 302 }, 7, ASPA_DOWNSTREAM) == ASPA_AS_PATH_INVALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 302, 402, 502, 999, 500, 400, 300 }, 7, ASPA_DOWNSTREAM) == ASPA_AS_PATH_UNKNOWN);

	// single nA at highest level is valid
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 999, 500, 400, 300 }, 4, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 300, 400, 500, 999 }, 4, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);

	// single nP at highest level is valid
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 999, 502, 402, 302 }, 4, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 302, 402, 502, 999 }, 4, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);

	// the last hop in the down ramp must be valid
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 999, 300, 400, 500 }, 4, ASPA_DOWNSTREAM) == ASPA_AS_PATH_UNKNOWN);
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 100, 300, 400, 500 }, 4, ASPA_DOWNSTREAM) == ASPA_AS_PATH_INVALID);

	// the first hop in the up ramp must be valid
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 500, 400, 300, 999 }, 4, ASPA_DOWNSTREAM) == ASPA_AS_PATH_UNKNOWN);
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 500, 400, 300, 100 }, 4, ASPA_DOWNSTREAM) == ASPA_AS_PATH_INVALID);

	// consecutive up-ramps are invalid
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 400, 300, 200, 502, 402, 302 }, 6, ASPA_DOWNSTREAM) == ASPA_AS_PATH_INVALID);

	// consecutive down-ramps are invalid
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 200, 300, 400, 302, 402, 502 }, 6, ASPA_DOWNSTREAM) == ASPA_AS_PATH_INVALID);

	// both down- and up-ramp are invalid
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 400, 300, 200, 302, 402, 502 }, 6, ASPA_DOWNSTREAM) == ASPA_AS_PATH_INVALID);

	// overlapping customer-provider-relationships
	// 103 --> 203 <--> 303 <--> 403 <-- 304
	assert(aspa_verify_as_path(aspa_table, (uint32_t []){ 304, 403, 303, 203, 103 }, 5, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);
}




static void test_single_collapse(uint32_t input[], size_t input_len, uint32_t output[], size_t output_len)
{
	size_t retlen = aspa_collapse_as_path(input, input_len);
	assert(retlen == output_len);
	for (size_t i = 0; i < output_len; i++) {
		assert(input[i] == output[i]);
	}
}

static void test_collapse()
{
	test_single_collapse((uint32_t []){}, 0, (uint32_t []){}, 0);
	test_single_collapse((uint32_t []){1}, 1, (uint32_t []){1}, 1);
	test_single_collapse((uint32_t []){1, 1}, 2, (uint32_t []){1}, 1);
	test_single_collapse((uint32_t []){1, 2}, 2, (uint32_t []){1, 2}, 2);
	test_single_collapse((uint32_t []){1, 1, 1}, 3, (uint32_t []){1}, 1);
	test_single_collapse((uint32_t []){1, 1, 2}, 3, (uint32_t []){1, 2}, 2);
	test_single_collapse((uint32_t []){1, 2, 2}, 3, (uint32_t []){1, 2}, 2);
	test_single_collapse((uint32_t []){1, 2, 2, 2}, 4, (uint32_t []){1, 2}, 2);
	test_single_collapse((uint32_t []){1, 2, 2, 3}, 4, (uint32_t []){1, 2, 3}, 3);
}

int main()
{
	struct aspa_table *aspa_table = test_create_aspa_table();
	test_hopping(aspa_table);
	test_upstream(aspa_table);
	test_downstream(aspa_table);
	test_collapse();
}