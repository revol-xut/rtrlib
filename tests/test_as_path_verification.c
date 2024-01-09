/*
* This file is part of RTRlib.
*
* This file is subject to the terms and conditions of the MIT license.
* See the file LICENSE in the top level directory for more details.
*
* Website; http://rtrlib.realmv6.org/
*/

#include "rtrlib/aspa/aspa_array/aspa_array.h"
#include "rtrlib/aspa/aspa_private.h"
#include "rtrlib/lib/alloc_utils_private.h"

#include <assert.h>
#include <string.h>

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

static void insert_new_socket_records(struct aspa_table *aspa_table, struct aspa_record **records, size_t record_count)
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
	records[i++] = create_aspa_record(100, (uint32_t[]){200, 201}, 2);
	records[i++] = create_aspa_record(200, (uint32_t[]){300}, 1);
	records[i++] = create_aspa_record(300, (uint32_t[]){400}, 1);
	records[i++] = create_aspa_record(400, (uint32_t[]){500}, 1);

	records[i++] = create_aspa_record(501, (uint32_t[]){601}, 1);
	records[i++] = create_aspa_record(401, (uint32_t[]){501}, 1);
	records[i++] = create_aspa_record(301, (uint32_t[]){401}, 1);
	records[i++] = create_aspa_record(201, (uint32_t[]){301}, 1);

	records[i++] = create_aspa_record(502, (uint32_t[]){602}, 1);
	records[i++] = create_aspa_record(402, (uint32_t[]){502}, 1);
	records[i++] = create_aspa_record(302, (uint32_t[]){402}, 1);
	records[i++] = create_aspa_record(202, (uint32_t[]){302}, 1);

	// 103 --> 203 <--> 303 <--> 403 <-- 304
	records[i++] = create_aspa_record(103, (uint32_t[]){203}, 1);
	records[i++] = create_aspa_record(203, (uint32_t[]){303}, 1);
	records[i++] = create_aspa_record(303, (uint32_t[]){203, 403}, 2);
	records[i++] = create_aspa_record(403, (uint32_t[]){303}, 1);
	records[i++] = create_aspa_record(304, (uint32_t[]){403}, 1);

	insert_new_socket_records(aspa_table, records, 17);

	struct aspa_record *records_2[1] = {create_aspa_record(100, (uint32_t[]){200, 202}, 2)};
	insert_new_socket_records(aspa_table, records_2, 1);

	return aspa_table;
}

static void test_hopping(struct aspa_table *aspa_table)
{
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

static void test_upstream(struct aspa_table *aspa_table)
{
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){}, 0, ASPA_UPSTREAM) == ASPA_AS_PATH_VALID);
	// TODO ^ this was invalid before

	// paths of length 1 are valid
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){100}, 1, ASPA_UPSTREAM) == ASPA_AS_PATH_VALID);

	// valid upstream paths
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){200, 100}, 2, ASPA_UPSTREAM) == ASPA_AS_PATH_VALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){300, 200}, 2, ASPA_UPSTREAM) == ASPA_AS_PATH_VALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){300, 200, 100}, 3, ASPA_UPSTREAM) == ASPA_AS_PATH_VALID);

	// single not-provider hop (nP)

	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){999, 100}, 2, ASPA_UPSTREAM) == ASPA_AS_PATH_INVALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){300, 999, 100}, 3, ASPA_UPSTREAM) == ASPA_AS_PATH_INVALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){999, 999, 100}, 3, ASPA_UPSTREAM) == ASPA_AS_PATH_INVALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){999, 100, 999}, 3, ASPA_UPSTREAM) == ASPA_AS_PATH_INVALID);

	// single unattested hop (nA)
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){999, 500, 400, 300}, 4, ASPA_UPSTREAM) ==
	       ASPA_AS_PATH_UNKNOWN);
}

static void test_downstream(struct aspa_table *aspa_table)
{
	// paths of length 1 <= N <= 2 are valid
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){999}, 1, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){998, 999}, 2, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);

	// either up- or down-ramp is valid, not both
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){300, 400, 500}, 3, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){500, 400, 300}, 3, ASPA_DOWNSTREAM) == ASPA_AS_PATH_VALID);

	// w/o customer-provider gap
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){300, 400, 500, 400, 300}, 5, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_VALID);

	// single not-provider (nP) in between
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){302, 402, 502, 500, 400, 300}, 6, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_VALID);

	// two highest-level hops are nP
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){301, 401, 501, 502, 502, 402, 302}, 7, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_INVALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){302, 402, 502, 999, 500, 400, 300}, 7, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_UNKNOWN);

	// single nA at highest level is valid
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){999, 500, 400, 300}, 4, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_VALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){300, 400, 500, 999}, 4, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_VALID);

	// single nP at highest level is valid
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){999, 502, 402, 302}, 4, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_VALID);
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){302, 402, 502, 999}, 4, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_VALID);

	// the last hop in the down ramp must be valid
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){999, 300, 400, 500}, 4, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_UNKNOWN);
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){100, 300, 400, 500}, 4, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_INVALID);

	// the first hop in the up ramp must be valid
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){500, 400, 300, 999}, 4, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_UNKNOWN);
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){500, 400, 300, 100}, 4, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_INVALID);

	// consecutive up-ramps are invalid
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){400, 300, 200, 502, 402, 302}, 6, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_INVALID);

	// consecutive down-ramps are invalid
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){200, 300, 400, 302, 402, 502}, 6, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_INVALID);

	// both down- and up-ramp are invalid
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){400, 300, 200, 302, 402, 502}, 6, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_INVALID);

	// overlapping customer-provider-relationships
	// 103 --> 203 <--> 303 <--> 403 <-- 304
	assert(aspa_verify_as_path(aspa_table, (uint32_t[]){304, 403, 303, 203, 103}, 5, ASPA_DOWNSTREAM) ==
	       ASPA_AS_PATH_VALID);
}

/**
 * Example 1 (downstream) (valid)
 *
 * as_path: 20, 30, 40, 70, 80
 *
 *          30   40
 *  10  20           70
 *                       80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 40
 *   20: 30
 *
 */
static void test_verify_example_1()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(80, (uint32_t[]){70}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(70, (uint32_t[]){40}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){30}, 1), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_DOWNSTREAM, (uint32_t[]){20, 30, 40, 70, 80}, 5) ==
	       ASPA_AS_PATH_VALID);
}

/**
 * Example 2 (downstream) (unknown)
 *
 * as_path: 20, 30, 90, 40, 70, 80
 *
 *          30      40
 *  10  20      90      70
 *                          80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 40
 *   20: 30
 *   90: 30, 40
 *
 */
static void test_verify_example_2()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(80, (uint32_t[]){70}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(70, (uint32_t[]){40}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){30}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(90, (uint32_t[]){30, 40}, 2), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_DOWNSTREAM, (uint32_t[]){20, 30, 90, 40, 70, 80}, 6) ==
	       ASPA_AS_PATH_UNKNOWN);
}

/**
 * Example 2b (downstream) (invalid)
 *
 * as_path: 20, 30, 90, 40, 70, 80
 *
 *          30*      40*
 *  10  20       90      70
 *                           80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 40
 *   20: 30
 *   90: 30, 40
 *   30:   (none)
 *   40:   (none)
 *
 */
static void test_verify_example_2b()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(80, (uint32_t[]){70}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(70, (uint32_t[]){40}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){30}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(90, (uint32_t[]){30, 40}, 2), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(30, (uint32_t[]){}, 0), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(40, (uint32_t[]){}, 0), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_DOWNSTREAM, (uint32_t[]){20, 30, 90, 40, 70, 80}, 6) ==
	       ASPA_AS_PATH_INVALID);
}

/**
 * Example 3a (downstream) (unknown)
 *
 * as_path: 20, 30, 90, 40, 70, 80
 *
 *          30   90  40
 *      20               70
 *  10                       80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 40
 *   20: 30
 *
 */
static void test_verify_example_3a()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(80, (uint32_t[]){70}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(70, (uint32_t[]){40}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){30}, 1), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_DOWNSTREAM, (uint32_t[]){20, 30, 90, 40, 70, 80}, 6) ==
	       ASPA_AS_PATH_UNKNOWN);
}

/**
 * Example 3b (downstream) (unknown)
 *
 * as_path: 20, 30, 90, 100, 40, 70, 80
 *
 *          30   90  100 40
 *  10  20                 70
 *                            80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 40
 *   20: 30
 *
 */
static void test_verify_example_3b()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(80, (uint32_t[]){70}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(70, (uint32_t[]){40}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){30}, 1), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_DOWNSTREAM, (uint32_t[]){20, 30, 90, 100, 40, 70, 80}, 7) ==
	       ASPA_AS_PATH_UNKNOWN);
}

/**
 * Example 3c (downstream) (invalid)
 *
 * as_path: 20, 30, 90, 100, 40, 70, 80
 *
 *       30*  90  100  40*
 *     20                 70
 *  10                      80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 40
 *   20: 30
 *   30:   (none)
 *   40:   (none)
 *
 */
static void test_verify_example_3c()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(80, (uint32_t[]){70}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(70, (uint32_t[]){40}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){30}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(30, (uint32_t[]){}, 0), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(40, (uint32_t[]){}, 0), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_DOWNSTREAM, (uint32_t[]){20, 30, 90, 100, 40, 70, 80}, 7) ==
	       ASPA_AS_PATH_INVALID);
}

/**
 * Example 3d (downstream) (unknown)
 *
 * as_path: 20, 30, 40, 100, 90, 70, 80
 *
 *          30*  40*  100?  90?
 *  10  20                       70
 *                                   80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 90
 *   20: 30
 *   30:   (none)
 *   40:   (none)
 *
 */
static void test_verify_example_3d()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(80, (uint32_t[]){70}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(70, (uint32_t[]){90}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){30}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(30, (uint32_t[]){}, 0), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(40, (uint32_t[]){}, 0), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_DOWNSTREAM, (uint32_t[]){20, 30, 40, 100, 90, 70, 80}, 7) ==
	       ASPA_AS_PATH_UNKNOWN);
}

/**
 * Example 3f (downstream) (unknown)
 *
 * as_path: 20, 30, 40, 100, 90, 70, 80
 *
 *          30  40  100  90
 *  10  20                   70
 *                               80 (origin)
 *
 * customer-providers:
 *   80: 70
 *   70: 90
 *   20: 30
 *   100:   (none)
 *   40:   (none)
 *
 */
static void test_verify_example_3f()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(80, (uint32_t[]){70}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(70, (uint32_t[]){90}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){30}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(100, (uint32_t[]){}, 0), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(40, (uint32_t[]){}, 0), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_DOWNSTREAM, (uint32_t[]){20, 30, 40, 100, 90, 70, 80}, 7) ==
	       ASPA_AS_PATH_UNKNOWN);
}

/**
 * Example 4 (upstream) (invalid)
 *
 * as_path: 20, 30, 40, 50, 60, 70, 80
 *
 *  10                               80 (origin)
 *    20   30    40    50   60   70
 *
 * customer-providers:
 *   70: 80
 *
 */
static void test_verify_example_4()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(70, (uint32_t[]){80}, 1), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_UPSTREAM, (uint32_t[]){20, 30, 40, 50, 60, 70, 80}, 7) ==
	       ASPA_AS_PATH_INVALID);
}

/**
 * Example 4-fixed (upstream) (invalid)
 *
 * as_path: 20, 30, 40, 50, 60, 70, 80
 *
 *  10                      80 (origin)
 *    20                70
 *      30  40  50  60
 *
 * customer-providers:
 *   70: 80
 *   60: 70
 *   30: 20
 *
 */
static void test_verify_example_4_fixed()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(70, (uint32_t[]){80}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(60, (uint32_t[]){70}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(30, (uint32_t[]){20}, 1), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_UPSTREAM, (uint32_t[]){20, 30, 40, 50, 60, 70, 80}, 7) ==
	       ASPA_AS_PATH_INVALID);
}

/**
 * Example 5 (upstream) (valid)
 *
 * as_path: 20, 30, 40
 *
 * 10  20
 *        30
 *           40 (origin)
 *
 * customer-providers:
 *   40: 30
 *   30: 20
 *
 */
static void test_verify_example_5()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(40, (uint32_t[]){30}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(30, (uint32_t[]){20}, 1), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_UPSTREAM, (uint32_t[]){20, 30, 40}, 3) == ASPA_AS_PATH_VALID);
}

/**
 * Example 6 (downstream) (invalid)
 *
 * as_path: 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120
 *
 *         50         90
 *       40  60 70 80   100
 *     30                  110
 *   20                       120
 * 10
 *
 * customer-providers:
 *   120: 110
 *   110: 100
 *   100: 90
 *   80: 90
 *   60: 50
 *   40: 50
 *   30: 40
 *   20: 30
 *
 */
static void test_verify_example_6()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(120, (uint32_t[]){110}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(110, (uint32_t[]){100}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(100, (uint32_t[]){90}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(80, (uint32_t[]){90}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(60, (uint32_t[]){50}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(40, (uint32_t[]){50}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(30, (uint32_t[]){40}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){30}, 1), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_DOWNSTREAM,
				   (uint32_t[]){20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120},
				   11) == ASPA_AS_PATH_INVALID);
}

/**
 * Example 7 (downstream) (unknown)
 *
 * as_path: 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140
 *
 * read from right: 100 -U-> 90 -U-> 80 -U-> 70 -U-> 60 -U-> 50
 * read from left: 50 -U-> 60 -U-> 70 -U-> 80 -P+-> 90 -P+-> 100
 *
 *                        100
 *                     90     110
 *         50 60 70 80           120
 *       40                         130
 *     30                              140
 *   20
 * 10
 *
 * customer-providers:
 *   20: 30
 *   30: 40
 *   40: 50
 *   80: 90
 *   90: 100
 *   110: 100
 *   120: 110
 *   130: 120
 *   140: 130
 *
 */
static void test_verify_example_7()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){30}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(30, (uint32_t[]){40}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(40, (uint32_t[]){50}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(80, (uint32_t[]){90}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(90, (uint32_t[]){100}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(110, (uint32_t[]){100}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(120, (uint32_t[]){110}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(130, (uint32_t[]){120}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(140, (uint32_t[]){130}, 1), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_DOWNSTREAM,
				   (uint32_t[]){20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140},
				   13) == ASPA_AS_PATH_UNKNOWN);
}

/**
 * Example 8 (downstream) (valid)
 *
 * as_path: 20
 *
 *   20
 * 10
 *
 * customer-providers:
 * (none)
 *
 */
static void test_verify_example_8()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	assert(aspa_verify_as_path(aspa_table, ASPA_DOWNSTREAM, (uint32_t[]){20}, 1) == ASPA_AS_PATH_VALID);
}

/**
 * Example 9 (upstream) (valid)
 *
 * as_path: 20
 *
 * 10
 *   20
 *
 * customer-providers:
 * (none)
 *
 */
static void test_verify_example_9()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	assert(aspa_verify_as_path(aspa_table, ASPA_UPSTREAM, (uint32_t[]){20}, 1) == ASPA_AS_PATH_VALID);
}

/**
 * Example 11 (downstream) (valid)
 *
 * as_path: 20, 30
 *
 *   20 30
 *
 * customer-providers:
 *   20:   (none)
 *   30:   (none)
 *
 */
static void test_verify_example_11()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){}, 0), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(30, (uint32_t[]){}, 0), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_DOWNSTREAM, (uint32_t[]){20, 30}, 2) == ASPA_AS_PATH_VALID);
}

/**
 * Example 12 (upstream) (unknown)
 *
 * as_path: 20, 30
 *
 *   20 30
 *
 * customer-providers:
 * (none)
 *
 */
static void test_verify_example_12()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	assert(aspa_verify_as_path(aspa_table, ASPA_UPSTREAM, (uint32_t[]){20, 30}, 2) == ASPA_AS_PATH_UNKNOWN);
}

/**
 * Example 13 (upstream) (invalid)
 *
 * as_path: 20, 30, 40, 50, 60
 *
 *   20
 *      30
 *         40  50
 *               60
 *
 * customer-providers:
 *   60: 50
 *   50:   (none)
 *   40: 30
 *   30: 20
 *   20:   (none)
 *
 */
static void test_verify_example_13()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(60, (uint32_t[]){50}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(50, (uint32_t[]){}, 0), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(40, (uint32_t[]){30}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(30, (uint32_t[]){20}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){}, 0), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_UPSTREAM, (uint32_t[]){20, 30, 40, 50, 60}, 5) ==
	       ASPA_AS_PATH_INVALID);
}

/**
 * Example 14 (upstream) (invalid)
 *
 * as_path: 20, 30, 40, 50, 60
 *
 *     30 <> 40 <> 50 <> 60
 *  20
 *
 * customer-providers:
 *   60: 50
 *   50: 40, 60
 *   40: 30, 50
 *   30: 40
 *   20: 30
 *
 */
static void test_verify_example_14()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(60, (uint32_t[]){50}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(50, (uint32_t[]){40, 60}, 2), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(40, (uint32_t[]){30, 50}, 2), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(30, (uint32_t[]){40}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){30}, 1), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_UPSTREAM, (uint32_t[]){20, 30, 40, 50, 60}, 5) ==
	       ASPA_AS_PATH_INVALID);
}

/**
 * Example 15 (upstream) (invalid)
 *
 * as_path: 20, 30, 40, 50, 60
 *
 *       30 <> 40 <> 50 <> 60
 *   20
 *
 * customer-providers:
 *   60: 50, 20
 *   50: 40, 60
 *   40: 30, 50
 *   30: 40
 *   20: 30
 *
 */
static void test_verify_example_15()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(60, (uint32_t[]){50, 20}, 2), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(50, (uint32_t[]){40, 60}, 2), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(40, (uint32_t[]){30, 50}, 2), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(30, (uint32_t[]){40}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){30}, 1), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_UPSTREAM, (uint32_t[]){20, 30, 40, 50, 60}, 5) ==
	       ASPA_AS_PATH_INVALID);
}

/**
 * Example 16 (upstream) (invalid)
 *
 * as_path: 10, 20, 30, 40
 *
 *     20   30
 * 10           40
 *
 * customer-providers:
 *   10: 20
 *   20: 100
 *   40: 30
 *
 */
static void test_verify_example_16()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(10, (uint32_t[]){20}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){100}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(40, (uint32_t[]){30}, 1), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_UPSTREAM, (uint32_t[]){10, 20, 30, 40}, 4) == ASPA_AS_PATH_INVALID);
}

/**
 * Example 17 (upstream) (invalid)
 *
 * as_path: 10, 20, 30, 40
 *
 *                 X
 *     20      40
 * 10      30
 *
 * customer-providers:
 *   10: 20
 *   20: 100
 *   40: 30, 50
 *   50: 40
 *
 */
static void test_verify_example_17()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(10, (uint32_t[]){20}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){100}, 1), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(40, (uint32_t[]){30, 50}, 2), rtr_socket, false);
	aspa_table_add(aspa_table, create_aspa_record(50, (uint32_t[]){40}, 1), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_UPSTREAM, (uint32_t[]){10, 20, 30, 40}, 4) == ASPA_AS_PATH_INVALID);
}

/**
 * Example 18 (upstream) (invalid)
 *
 * as_path: 30, 20, 40
 *
 *  30  20*  40
 *
 * customer-providers:
 *   20:   (none)
 *
 */
static void test_verify_example_18()
{
	struct aspa_table *aspa_table = lrtr_malloc(sizeof(*aspa_table));
	assert(aspa_table != NULL);
	aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_array = NULL;

	aspa_table_add(aspa_table, create_aspa_record(20, (uint32_t[]){}, 0), rtr_socket, false);

	assert(aspa_verify_as_path(aspa_table, ASPA_UPSTREAM, (uint32_t[]){30, 20, 40}, 3) == ASPA_AS_PATH_INVALID);
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
	test_single_collapse((uint32_t[]){}, 0, (uint32_t[]){}, 0);
	test_single_collapse((uint32_t[]){1}, 1, (uint32_t[]){1}, 1);
	test_single_collapse((uint32_t[]){1, 1}, 2, (uint32_t[]){1}, 1);
	test_single_collapse((uint32_t[]){1, 2}, 2, (uint32_t[]){1, 2}, 2);
	test_single_collapse((uint32_t[]){1, 1, 1}, 3, (uint32_t[]){1}, 1);
	test_single_collapse((uint32_t[]){1, 1, 2}, 3, (uint32_t[]){1, 2}, 2);
	test_single_collapse((uint32_t[]){1, 2, 2}, 3, (uint32_t[]){1, 2}, 2);
	test_single_collapse((uint32_t[]){1, 2, 2, 2}, 4, (uint32_t[]){1, 2}, 2);
	test_single_collapse((uint32_t[]){1, 2, 2, 3}, 4, (uint32_t[]){1, 2, 3}, 3);
}

int main()
{
	struct aspa_table *aspa_table = test_create_aspa_table();
	test_hopping(aspa_table);
	test_upstream(aspa_table);
	test_downstream(aspa_table);

	test_verify_example_1();
	test_verify_example_2();
	test_verify_example_2b();
	test_verify_example_3a();
	test_verify_example_3b();
	test_verify_example_3c();
	test_verify_example_3d();
	test_verify_example_3f();
	test_verify_example_4();
	test_verify_example_4_fixed();
	test_verify_example_5();
	test_verify_example_6();
	test_verify_example_7();
	test_verify_example_8();
	test_verify_example_9();
	test_verify_example_11();
	test_verify_example_12();
	test_verify_example_13();
	test_verify_example_14();
	test_verify_example_15();
	test_verify_example_16();
	test_verify_example_17();
	test_verify_example_18();

	test_collapse();
}
