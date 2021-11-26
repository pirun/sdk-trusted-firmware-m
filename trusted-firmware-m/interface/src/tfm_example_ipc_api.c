/*
 * Copyright (c) 2017-2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include "psa/client.h"
#include "psa/tfm_example.h"
#include "psa_manifest/sid.h"
#include "tfm_ns_interface.h"

psa_status_t rot_a_input_output(const void **in_data,
                        size_t in_data_count,
                        const void **out_data,
                        size_t out_data_count)
{
    psa_status_t status = PSA_SUCCESS;

    return status;
}

psa_status_t rot_b_crypto_hash(const void *in_data,
                        const void *out_data)
{
    psa_status_t status = PSA_SUCCESS;

    return status;
}

psa_status_t rot_c_crypto_rand(const void *out_data)
{
    psa_status_t status = PSA_SUCCESS;

    return status;
}
