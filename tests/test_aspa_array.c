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

static void test_create_array(void)
{
	struct aspa_array *array;

	assert(aspa_array_create(&array) == ASPA_SUCCESS);
	assert(array->data);
	assert(array->size == 0);
	assert(array->capacity >= 128);
};

static void generate_fake_aspa_record(uint32_t cas, uint32_t random_number, struct aspa_record **record)
{
	struct aspa_record *new_record = lrtr_malloc(sizeof(struct aspa_record));

	new_record->customer_asn = cas;
	uint32_t *provider_asns = lrtr_malloc(sizeof(*new_record->provider_asns) * 3);

	for (size_t i = 0; i < 3; i++)
		provider_asns[i] = random_number + i;

	new_record->provider_count = 3;
	new_record->provider_asns = provider_asns;
	*record = new_record;
}

static void test_add_element(void)
{
	struct aspa_array *array;

	assert(aspa_array_create(&array) == ASPA_SUCCESS);

	struct aspa_record *record;

	generate_fake_aspa_record(42, 300, &record);
	assert(aspa_array_insert(array, 0, record, false) == 0);
	assert(array->data[0].customer_asn == 42);
	assert(array->data[0].provider_count == 3);
	assert(array->data[0].provider_asns[0] == 300);
	assert(array->data[0].provider_asns[1] == 300 + 1);
	assert(array->data[0].provider_asns[2] == 300 + 2);

	aspa_array_free(array, true);
}

static void test_insert(void)
{
	struct aspa_array *array;

	assert(aspa_array_create(&array) == ASPA_SUCCESS);
	array->capacity = 2;
	struct aspa_record *old_pointer = array->data;

	struct aspa_record *record_4;

	generate_fake_aspa_record(4, 600, &record_4);
	assert(aspa_array_insert(array, 0, record_4, false) == ASPA_SUCCESS);

	struct aspa_record *record_2;

	generate_fake_aspa_record(2, 400, &record_2);
	assert(aspa_array_insert(array, 1, record_2, false) == ASPA_SUCCESS);

	struct aspa_record *record_1;

	generate_fake_aspa_record(1, 300, &record_1);
	assert(aspa_array_insert(array, 2, record_1, false) == ASPA_SUCCESS);

	struct aspa_record *record_3;

	generate_fake_aspa_record(3, 500, &record_3);
	assert(aspa_array_insert(array, 3, record_3, false) == ASPA_SUCCESS);

	assert(old_pointer != array->data); // new pointer because relocated
	assert(array->capacity >= 4);
	assert(array->size == 4);

	assert(array->data[0].customer_asn == 4);
	assert(array->data[1].customer_asn == 2);
	assert(array->data[2].customer_asn == 1);
	assert(array->data[3].customer_asn == 3);

	aspa_array_free(array, true);
}

static void test_append(void)
{
	struct aspa_array *array;

	assert(aspa_array_create(&array) == ASPA_SUCCESS);
	array->capacity = 2;
	struct aspa_record *old_pointer = array->data;

	struct aspa_record *record_4;

	generate_fake_aspa_record(4, 600, &record_4);
	assert(aspa_array_append(array, record_4, false) == ASPA_SUCCESS);

	struct aspa_record *record_2;

	generate_fake_aspa_record(2, 400, &record_2);
	assert(aspa_array_append(array, record_2, false) == ASPA_SUCCESS);

	struct aspa_record *record_1;

	generate_fake_aspa_record(1, 300, &record_1);
	assert(aspa_array_append(array, record_1, false) == ASPA_SUCCESS);

	struct aspa_record *record_3;

	generate_fake_aspa_record(3, 500, &record_3);
	assert(aspa_array_append(array, record_3, false) == ASPA_SUCCESS);

	assert(old_pointer != array->data); // new pointer because relocated
	assert(array->capacity >= 4);
	assert(array->size == 4);

	assert(array->data[0].customer_asn == 4);
	assert(array->data[1].customer_asn == 2);
	assert(array->data[2].customer_asn == 1);
	assert(array->data[3].customer_asn == 3);

	aspa_array_free(array, true);
}

static void test_remove_element(void)
{
	struct aspa_array *array;

	assert(aspa_array_create(&array) == 0);

	struct aspa_record *record_1;

	generate_fake_aspa_record(1, 300, &record_1);
	assert(aspa_array_insert(array, 0, record_1, false) == ASPA_SUCCESS);

	struct aspa_record *record_2;

	generate_fake_aspa_record(2, 400, &record_2);
	assert(aspa_array_insert(array, 1, record_2, false) == ASPA_SUCCESS);

	struct aspa_record *record_3;

	generate_fake_aspa_record(3, 500, &record_3);
	assert(aspa_array_insert(array, 2, record_3, false) == ASPA_SUCCESS);

	struct aspa_record *record_4;

	generate_fake_aspa_record(4, 600, &record_4);
	assert(aspa_array_insert(array, 3, record_4, false) == ASPA_SUCCESS);

	assert(array->data[2].customer_asn == 3);

	assert(aspa_array_remove(array, 2, true) == ASPA_SUCCESS);
	assert(aspa_array_remove(array, 100, true) == ASPA_RECORD_NOT_FOUND);

	assert(array->size == 3);
	assert(array->data[0].customer_asn == 1);
	assert(array->data[1].customer_asn == 2);
	assert(array->data[2].customer_asn == 4);

	aspa_array_free(array, true);
}

static void test_find_element(void)
{
	struct aspa_array *array;

	assert(aspa_array_create(&array) == 0);

	struct aspa_record *record_1;

	generate_fake_aspa_record(1, 300, &record_1);
	assert(aspa_array_insert(array, 0, record_1, false) == 0);

	struct aspa_record *record_2;

	generate_fake_aspa_record(2, 400, &record_2);
	assert(aspa_array_insert(array, 1, record_2, false) == 0);

	struct aspa_record *record_3;

	generate_fake_aspa_record(3, 500, &record_3);
	assert(aspa_array_insert(array, 2, record_3, false) == 0);

	struct aspa_record *record_4;

	generate_fake_aspa_record(4, 600, &record_4);
	assert(aspa_array_insert(array, 3, record_4, false) == 0);

	struct aspa_record *record_5;

	generate_fake_aspa_record(5, 700, &record_5);
	assert(aspa_array_insert(array, 4, record_5, false) == 0);

	assert(aspa_array_search(array, 1) == &array->data[0]);
	assert(aspa_array_search(array, 2) == &array->data[1]);
	assert(aspa_array_search(array, 3) == &array->data[2]);
	assert(aspa_array_search(array, 4) == &array->data[3]);
	assert(aspa_array_search(array, 5) == &array->data[4]);

	aspa_array_free(array, true);
}

int main(void)
{
	test_create_array();
	test_add_element();
	test_insert();
	test_append();
	test_remove_element();
	test_find_element();
}
