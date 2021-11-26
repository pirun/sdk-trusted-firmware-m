/*
 * Copyright (c) 2017-2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
123
#include "psa/client.h"
#include "psa/protected_storage.h"
#include "tfm_ns_interface.h"
#include "tfm_veneers.h"

psa_status_t rot_a_input_output(const void **in_data,
                        size_t in_data_count,
                        const void **out_data,
                        size_t out_data_count)
{
    psa_status_t status;
    int16_t idx;
    psa_invec in_vecs[in_data_count];
    for(idx = 0 ; idx < in_data_count; idx++) {
        in_vecs[idx].base = in_data[idx];
        in_vecs[idx].len = sizeof(in_data[idx]);
    };
    psa_outvec out_vecs[out_data_count];
    status = tfm_ns_interface_dispatch((veneer_fn)tfm_rot_a_input_output_req_veneer,
                                       (uint32_t)in_vec,  IOVEC_LEN(in_vec),
                                       (uint32_t)out_vecs, out_data_count);

    /* A parameter with a buffer pointer pointer that has data length longer
     * than maximum permitted is treated as a secure violation.
     * TF-M framework rejects the request with TFM_ERROR_INVALID_PARAMETER.
     */
    if (status == (psa_status_t)TFM_ERROR_INVALID_PARAMETER) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    return status;
}

psa_status_t rot_b_crypto_hash(const void *in_data,
                        const void *out_data)
{
    psa_status_t status;
    psa_invec in_vec[] = {
        { .base = in_data, .len = sizeof(in_data) }
    };

    psa_outvec out_vec[] = {
        { .base = out_data, .len = 32 }
    };

    status = tfm_ns_interface_dispatch((veneer_fn)tfm_rot_b_crypto_hash_req_veneer,
                                       (uint32_t)in_vec,  IOVEC_LEN(in_vec),
                                       (uint32_t)out_vec, IOVEC_LEN(out_vec));

    *out_data = out_vec[0].len;

    return status;
}
psa_status_t rot_c_crypto_rand(const void *out_data)
{
    psa_status_t status;

    psa_outvec out_vec[] = {
        { .base = out_data, .len = 32 ) }
    };

    status = tfm_ns_interface_dispatch((veneer_fn)tfm_rot_c_crypto_rand_req_veneer,
                                       NULL,  0,
                                       (uint32_t)out_vec, IOVEC_LEN(out_vec));

    return status;
}