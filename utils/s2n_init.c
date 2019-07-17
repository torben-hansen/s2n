/*
 * Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
#include "crypto/s2n_fips.h"

#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_cipher_suites.h"

#include "utils/s2n_mem.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

#include "openssl/opensslv.h"

#include <stdlib.h>

static void s2n_cleanup_atexit(void);

unsigned long s2n_get_openssl_version(void)
{
    return OPENSSL_VERSION_NUMBER;
}

int s2n_init(void)
{
    GUARD(s2n_fips_init());
    GUARD(s2n_mem_init());

#if defined(ENABLE_UNSAFE_AWSLC_ENGINE)
    /* Attempt to load AWS-LC engine. If AWS-LC engine flag is set, we regard a
     * failure to load the AWS-LC engine an error and abort. This condition
     * could be relaxed. The function call reads the environment variable
     * |OPENSSL_CONF| that should point to an OpenSSL config file. This config
     * file must configure the use of the AWS-LC engine. An example of such a
     * file can be found in /crypto/awslc_engine.conf.
     *
     * Firstly, verify at run-time that the engine should actually be loaded.
     * This requires a consumer to be concious about the choice at both
     * compile-time and run-time.
     */
    if (NULL == getenv("USE_UNSAFE_AWSLC_ENGINE")) {
        /* Inconsistency between choice at compile-time and run-time, abort */
        return -1;
    }

    /* TODO If this function succeeds, the engine might not have been loaded.
     * This could happen if OpenSSL was unable to find the AWS-LC engine.
     */
    GUARD(1 > OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ENGINE_DYNAMIC, NULL));
#endif

    GUARD(s2n_rand_init());
    GUARD(s2n_cipher_suites_init());
    GUARD(s2n_cipher_preferences_init());

    S2N_ERROR_IF(atexit(s2n_cleanup_atexit) != 0, S2N_ERR_ATEXIT);

    /* these functions do lazy init. Avoid the race conditions and just do it here. */
    if (s2n_is_in_fips_mode()) {
        s2n_fetch_default_fips_config();
    } else {
        s2n_fetch_default_config();
    }

    return 0;
}

int s2n_cleanup(void)
{
    GUARD(s2n_rand_cleanup_thread());

    return 0;
}

static void s2n_cleanup_atexit(void)
{
    s2n_rand_cleanup_thread();
    s2n_rand_cleanup();
    s2n_mem_cleanup();
    s2n_wipe_static_configs();
}

