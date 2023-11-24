/*
* This file is part of RTRlib.
*
* This file is subject to the terms and conditions of the MIT license.
* See the file LICENSE in the top level directory for more details.
*
* Website; http://rtrlib.realmv6.org/
*/

#include "rtrlib/lib/alloc_utils_private.h"
#include "rtrlib/aspa/aspa.h"
#include "rtrlib/aspa/aspa_array/aspa_tree.h"

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

static char *buffer_file(char *fname) {
    FILE *f = fopen(fname, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  /* same as rewind(f); */

    char *string = lrtr_malloc(fsize);
    fread(string, fsize, 1, f);
    fclose(f);
    return string;
}


int verify_as_path(struct aspa_table *aspa_table, struct rtr_socket* rtr_socket, char* f, size_t batch_size){
    uint32_t nwalks = *(uint32_t*)(&f[0]);
    long pos = sizeof(uint32_t);

    uint32_t plen = *(uint32_t*)(&f[pos]);
    pos += sizeof(uint32_t);

    for (int i = 0; i < nwalks; i++) {
        for (int j = 0; j < plen/batch_size; j++) {
            enum as_path_verification_result result = as_path_verify_upstream(aspa_table, (uint32_t*)&f[pos + j*batch_size*sizeof(uint32_t)], batch_size);
            if (result != AS_PATH_VALID) {
                return 1;
            }
        }
        pos += plen*sizeof(uint32_t);
    }
    return 0;
}

static struct aspa_table *load_aspa_table(struct aspa_table* aspa_table, struct rtr_socket* rtr_socket, char *f) {
    uint32_t len = *(uint32_t*)(&f[0]);
    long pos = sizeof(uint32_t);

    // struct aspa_array *vector;
    // assert(aspa_array_create(&vector) == 0);

    for (int i = len; i > 0; i--) {

        uint16_t pcount = *(uint32_t*)(&f[pos]);
        pos += sizeof(uint16_t);

        uint32_t cas = *(uint32_t*)(&f[pos]);
        pos += sizeof(uint32_t);

        struct aspa_record *record = (struct aspa_record *)lrtr_malloc(sizeof(struct aspa_record));
        record->customer_asn = cas;
        record->provider_count = pcount;

        // new_record->provider_asns = &f[pos];

        long size = pcount * sizeof(uint32_t);
        uint32_t *provider_asns = (uint32_t*)lrtr_malloc(size);
        memcpy(provider_asns, &f[pos], size);
        pos += size;
        record->provider_asns = provider_asns;

        assert(aspa_table_add(aspa_table, record, rtr_socket, false) == 0);
    }

    return ASPA_SUCCESS;
}

void run()
{
    struct aspa_table *aspa_table = (struct aspa_table*)lrtr_malloc(sizeof(struct aspa_table));
    aspa_table_init(aspa_table, NULL);

	struct rtr_socket *rtr_socket = lrtr_malloc(sizeof(*rtr_socket));
	assert(rtr_socket != NULL);
	rtr_socket->aspa_table = aspa_table;
	rtr_socket->aspa_tree = NULL;

    clock_t c[9];

    #define D(a,b) ((double)(c[b]-c[a])/CLOCKS_PER_SEC)
    #define D(b) ((double)(c[b]-c[b-1])/CLOCKS_PER_SEC)

    c[0] = clock();
    char *f = buffer_file("/home/moritz/code/oss/rtrlib/algo/aspa.dump");
    c[1] = clock();
	load_aspa_table(aspa_table, rtr_socket, f);
    c[2] = clock();

    printf("buffer %f parse %f ", D(1), D(2));

    char *w = buffer_file("/home/moritz/code/oss/rtrlib/algo/rwalks.dump");
    c[3] = clock();

    assert(verify_as_path(aspa_table, rtr_socket, w, 10) == 0);
    //assert(results[0] == AS_PATH_VALID);
    c[4] = clock();
    assert(verify_as_path(aspa_table, rtr_socket, w, 100) == 0);
    //assert(results[0] == AS_PATH_VALID);
    c[5] = clock();
    assert(verify_as_path(aspa_table, rtr_socket, w, 1000) == 0);
    c[6] = clock();
    assert(verify_as_path(aspa_table, rtr_socket, w, 2500) == 0);
    c[7] = clock();
    assert(verify_as_path(aspa_table, rtr_socket, w, 7500) == 0);
    c[8] = clock();


    printf("buffer %f verify 10: %f 100: %f 1000: %f 2500: %f 7500: %f\n",
        D(3), D(4), D(5), D(6), D(7), D(8));

}

int main() {
    for (int i = 0; i < 20; i++) {
        run();
    }
    return 0;
}

