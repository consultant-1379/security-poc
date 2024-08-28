/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.kaps.common.generator;

import javax.crypto.SecretKey;
import javax.inject.Inject;

import com.ericsson.oss.itpf.security.kaps.common.persistence.handler.SymmetricKeyPersistenceHandler;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;

public class SymmetricKeyGenerator {

    private SecretKey secretKey;

    @Inject
    SymmetricKeyPersistenceHandler symmetricKeyPersistenceHandler;

    /**
     * Generate and fetch SecretKey only one time.
     *
     * @return secret key
     * @throws KeyAccessProviderServiceException
     *             Thrown to indicate any internal database errors
     */
    public SecretKey getSecretKey() throws KeyAccessProviderServiceException {
        if (secretKey == null) {
            secretKey = symmetricKeyPersistenceHandler.fetchOrGenerateSecretKey();
        }

        return secretKey;
    }
}