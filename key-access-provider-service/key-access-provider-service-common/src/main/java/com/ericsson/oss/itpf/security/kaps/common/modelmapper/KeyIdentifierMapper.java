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
package com.ericsson.oss.itpf.security.kaps.common.modelmapper;

import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;

/**
 * Class which maps data models to JPA and vice versa.
 *
 */
public class KeyIdentifierMapper {

    /**
     * Maps to {@link KeyIdentifier} model.
     *
     * @param keyId
     *            id to be mapped with model
     * @return mapped model.
     */
    public KeyIdentifier toModel(final String keyId) {
        final KeyIdentifier keyIdentifier = new KeyIdentifier();
        keyIdentifier.setId(keyId);

        return keyIdentifier;
    }
}
