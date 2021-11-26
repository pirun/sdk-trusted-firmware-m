/*
 * Copyright (c) 2020 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <assert.h>
#include <stdio.h>

#include "tfm_spm_log.h"
#include "tfm_sp_log.h"
#include "psa_manifest/tfm_example.h"
#include "psa/crypto.h"
#include "tfm_crypto_defs.h"
#include "tfm_memory_utils.h"
#ifdef TFM_PSA_API
#include "psa/service.h"
#endif

#define DIGEST_SIZE 32
#define BUFFER_LEN 100

#define ROT_A_SEND_TEMPLATE " Hello World outvec"
void rot_a_operation(void *in_data, void *out_data)
{
    LOG_DBGFMT("%s\n", __func__);
    (void)tfm_memcpy(out_data, in_data, sizeof(in_data));
    (void)tfm_memcpy((out_data + sizeof(in_data) - 1), ROT_A_SEND_TEMPLATE, sizeof(ROT_A_SEND_TEMPLATE));
}

psa_status_t rot_b_operation(void *in_data, void *out_data)
{
    size_t hash_length;
    psa_status_t r;
    //try hash something here
    LOG_DBGFMT("%s\n",__func__);
    r = psa_hash_compute(PSA_ALG_SHA_256,
                        in_data,
                        BUFFER_LEN,
                        out_data,
                        DIGEST_SIZE,
                        &hash_length);
    if(r != PSA_SUCCESS) {
        LOG_DBGFMT("psa_hash_compute failed %d\n", r);
    }
    return r ;
}

psa_status_t rot_c_operation(void *out_data, size_t out_size)
{
    psa_status_t r;

    LOG_DBGFMT("%s\n",__func__);
    r = psa_generate_random(out_data, out_size);
    if(r != PSA_SUCCESS) {
        LOG_DBGFMT("rot_c_operation\npsa_generate_random failed %d\n", r);
    }
}
#if !defined(TFM_PSA_API)
//secure library mode
psa_status_t rot_a_input_output_req(psa_invec *in_vec, size_t in_len,
                            psa_outvec *out_vec, size_t out_len)
{
    psa_status_t status = PSA_SUCCESS;
    LOG_DBGFMT("%s\n", __func__);

    return status;
}
psa_status_t rot_b_crypto_hash_req(psa_invec *in_vec, size_t in_len,
                            psa_outvec *out_vec, size_t out_len)
{
    psa_status_t status = PSA_SUCCESS;
    LOG_DBGFMT("%s\n", __func__);

    return status;
}psa_status_t rot_c_crypto_rand_req(psa_invec *in_vec, size_t in_len,
                            psa_outvec *out_vec, size_t out_len)
{
    psa_status_t status = PSA_SUCCESS;
    LOG_DBGFMT("%s\n", __func__);

    return status;
}
#else
/* Define the whether the service is inuse flag. */
static uint32_t service_in_use = 0;
typedef psa_status_t (*example_func_t)(void);
static psa_msg_t msg;

static void example_signal_handle(psa_signal_t signal, example_func_t pfn)
{
    psa_status_t status;

    status = psa_get(signal, &msg);
    switch (msg.type) {
    case PSA_IPC_CONNECT:
        SPMLOG_INFMSG("example_signal_handle PSA_IPC_CONNECT\n");
        if (service_in_use & signal) {
            status = PSA_ERROR_CONNECTION_REFUSED;
        } else {
            service_in_use |= signal;
            status = PSA_SUCCESS;
        }        
        psa_reply(msg.handle, PSA_SUCCESS);
        SPMLOG_INFMSG("example_signal_handle replay after PSA_IPC_CONNECT\n");
        break;
    case PSA_IPC_CALL:
        SPMLOG_INFMSG("example_signal_handle PSA_IPC_CALL\n");
        status = pfn();
        SPMLOG_INFMSG("example_signal_handle psa_reply\n");
        psa_reply(msg.handle, status);
        break;
    case PSA_IPC_DISCONNECT:
        SPMLOG_INFMSG("example_signal_handle PSA_IPC_DISCONNECT\n");
        assert((service_in_use & signal) != 0);
        service_in_use &= ~signal;
        psa_reply(msg.handle, PSA_SUCCESS);
        break;
    default:
        psa_panic();
    }
}

//This is a simple input/output communication between non-secure and secure world.
//This function handle all signal type by itself

static void rot_A(void)
{
    psa_status_t r;
    int i;
    uint8_t rec_buf[BUFFER_LEN];
    char send_buf[BUFFER_LEN];
    size_t rec_len;

    psa_get(ROT_A_INPUT_OUTPUT_SIGNAL, &msg);
    switch (msg.type) {
    case PSA_IPC_CONNECT:
        if (service_in_use & ROT_A_INPUT_OUTPUT_SIGNAL) {
            r = PSA_ERROR_CONNECTION_REFUSED;
        } else {
            service_in_use |= ROT_A_INPUT_OUTPUT_SIGNAL;
            r = PSA_SUCCESS;
        }
        psa_reply(msg.handle, r);
        break;
    case PSA_IPC_CALL:
        for (i = 0; i < PSA_MAX_IOVEC; i++) {
            if (msg.in_size[i] != 0) {
                rec_len = psa_read(msg.handle, i, rec_buf, BUFFER_LEN);
                LOG_DBGFMT("rot_A read from non-secure world:\n%s count %d\n", rec_buf , rec_len);
            }
            if (msg.out_size[i] != 0) {
                rot_a_operation(rec_buf, send_buf);
                psa_write(msg.handle, i, send_buf, BUFFER_LEN);
            }
        }
        psa_reply(msg.handle, PSA_SUCCESS);
        break;
    case PSA_IPC_DISCONNECT:
        assert((service_in_use & ROT_A_INPUT_OUTPUT_SIGNAL) != 0);
        service_in_use &= ~ROT_A_INPUT_OUTPUT_SIGNAL;
        psa_reply(msg.handle, PSA_SUCCESS);
        break;
    default:
        /* cannot get here [broken SPM] */
        psa_panic();
        break;
    }
}
//This is a simple input/output communication between non-secure and secure world.
//This function only handle PSA_IPC_CALL.
//The other signals are handled by example_signal_handle.
static psa_status_t rot_A_by_handle_ipc(void)
{
    int i;
    uint8_t rec_buf[BUFFER_LEN];
    char send_buf[BUFFER_LEN];
    size_t rec_len;

    LOG_DBGFMT("rot_A call by signal handle\n");
    for (i = 0; i < PSA_MAX_IOVEC; i++) {
        if (msg.in_size[i] != 0) {
            rec_len = psa_read(msg.handle, i, rec_buf, BUFFER_LEN);
            LOG_DBGFMT("rot_A read from non-secure world:\n%s count %d\n", rec_buf, rec_len);
        }
        if (msg.out_size[i] != 0) {
            rot_a_operation(rec_buf, send_buf);
            psa_write(msg.handle, i, send_buf, BUFFER_LEN);
        }
    }
    return PSA_SUCCESS;
}
void rot_B(void)
{
    psa_status_t r;
    int i;
    uint8_t rec_buf[BUFFER_LEN];
    char send_buf[DIGEST_SIZE];
    size_t hash_length;
    size_t rec_len;

    psa_get(ROT_B_CRYPTO_HASH_SIGNAL, &msg);
    switch (msg.type) {
    case PSA_IPC_CONNECT:
        if (service_in_use & ROT_B_CRYPTO_HASH_SIGNAL) {
            r = PSA_ERROR_CONNECTION_REFUSED;
        } else {
            service_in_use |= ROT_B_CRYPTO_HASH_SIGNAL;
            r = PSA_SUCCESS;
        }
        psa_reply(msg.handle, r);
        break;
    case PSA_IPC_CALL:
        for (i = 0; i < PSA_MAX_IOVEC; i++) {
            if (msg.in_size[i] != 0) {
                rec_len = psa_read(msg.handle, i, rec_buf, BUFFER_LEN);
                LOG_DBGFMT("rot_B read from non-secure world:\n%s count %d\n", rec_buf, rec_len);
                rot_b_operation(rec_buf, send_buf);
            }
            if (msg.out_size[i] != 0) {                
                psa_write(msg.handle, i, send_buf, DIGEST_SIZE);
            }
        }
        psa_reply(msg.handle, PSA_SUCCESS);
        break;
    case PSA_IPC_DISCONNECT:
        assert((service_in_use & ROT_B_CRYPTO_HASH_SIGNAL) != 0);
        service_in_use &= ~ROT_B_CRYPTO_HASH_SIGNAL;
        psa_reply(msg.handle, PSA_SUCCESS);
        break;
    default:
        /* cannot get here [broken SPM] */
        psa_panic();
        break;
    }
}

static psa_status_t rot_B_by_handle_ipc(void)
{
    psa_status_t r;
    size_t hash_length = 0;
    int i;
    uint8_t rec_buf[BUFFER_LEN];
    char send_buf[DIGEST_SIZE];
    size_t rec_len;

    LOG_DBGFMT("rot_B call by signal handle\n");
    for (i = 0; i < PSA_MAX_IOVEC; i++) {
        if (msg.in_size[i] != 0) {
            rec_len = psa_read(msg.handle, i, rec_buf, BUFFER_LEN);
            LOG_DBGFMT("rot_B read from non-secure world:\n%s count %d\n", rec_buf, rec_len);
            rot_b_operation(rec_buf, send_buf);
            LOG_DBGFMT("rot_B hash %x\n",send_buf);
        }
        if (msg.out_size[i] != 0) {                
            psa_write(msg.handle, i, send_buf, DIGEST_SIZE);
        }
    }

    return PSA_SUCCESS;
}
static psa_status_t rot_C_by_handle_ipc(void)
{
    #define BUFFER_LEN 100

    psa_status_t r;
    size_t hash_length = 0;
    int i;
    uint8_t rec_buf[BUFFER_LEN];
	uint8_t random_bytes[DIGEST_SIZE];
    size_t rec_len;

    LOG_DBGFMT("rot_C call by signal handle\n");
    for (i = 0; i < PSA_MAX_IOVEC; i++) {
        if (msg.out_size[i] != 0) {
            rot_c_operation(random_bytes, DIGEST_SIZE);
            psa_write(msg.handle, i, random_bytes, DIGEST_SIZE);
        }
    }
    return PSA_SUCCESS;
}

#endif //TFM_PSA_API

psa_status_t example_main()
{

    SPMLOG_INFMSG("Custom service this_hello entry main\n");
#ifdef TFM_PSA_API
    psa_signal_t signals = 0;

    SPMLOG_INFMSG("Custom service IPC MODE\n");
    //In IPC mode , we need a infinite loop to handle incoming signal
    while (1) {
        signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
        if (signals & ROT_A_INPUT_OUTPUT_SIGNAL) {
            //pass to handle or call directly ,choose one

            //pass to handle
            example_signal_handle(ROT_A_INPUT_OUTPUT_SIGNAL, rot_A_by_handle_ipc);

            //call directly
            //rot_A();

        } else if (signals & ROT_B_CRYPTO_HASH_SIGNAL) {
            //pass to handle or call directly ,choose one

            //pass to handle
            example_signal_handle(ROT_B_CRYPTO_HASH_SIGNAL, rot_B_by_handle_ipc);
            
            //call directly
            //rot_B();
        } else if (signals & ROT_C_CRYPTO_RAND_SIGNAL) {
            example_signal_handle(ROT_C_CRYPTO_RAND_SIGNAL, rot_C_by_handle_ipc);
        } else {
            /* Should not come here */
            psa_panic();
        }
    }    
#else
    SPMLOG_DBGMSG("Custom service secure library MODE\n");
    return PSA_SUCCESS;
#endif
}
