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
package com.ericsson.oss.itpf.security.pki.core.common.modelmapper;

import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.KeyIdentifierData;

/**
 * Class to perform mapping between Object model and JPA model
 * 
 * @author xramcho
 *
 */
public class KeyIdentifierModelMapper {

    /**
     * Maps the {@link KeyIdentifier} to {@link KeyIdentifierData} JPA.
     * 
     * @param keyIdentifier
     *            Key identifier object for retrieving keys.
     * @param keyPairStatus
     *            Status of the keyIdentifier.
     * 
     * @return Mapped JPA {@link KeyIdentifierData}
     */
    public KeyIdentifierData fromModel(final KeyIdentifier keyIdentifier, final KeyPairStatus keyPairStatus) {

        final KeyIdentifierData keyData = new KeyIdentifierData();
        keyData.setKeyIdentifier(keyIdentifier.getId());
        keyData.setStatus(keyPairStatus);

        return keyData;
    }

    /**
     * Maps the {@link KeyIdentifierData} JPA to {@link KeyIdentifier} model.
     * 
     * @param keyIdentifierData
     *            {@link KeyIdentifierData} JPA.
     * 
     * @return Mapped {@link KeyIdentifier}
     */
    public KeyIdentifier toModel(final KeyIdentifierData keyIdentifierData) {

        final KeyIdentifier keyIdentifier = new KeyIdentifier();
        keyIdentifier.setId(keyIdentifierData.getKeyIdentifier());

        return keyIdentifier;
    }

}
