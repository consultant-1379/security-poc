/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test;

import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.KeyIdentifierData;

public class KeySetUpData {

    /**
     * Method that returns valid KeyData object
     * 
     * @return KeyData
     */
    public KeyIdentifierData getKeyIdentifierDataForCreate() {

        final KeyIdentifierData keyData = new KeyIdentifierData();
        keyData.setId(1L);
        keyData.setStatus(KeyPairStatus.ACTIVE);
        keyData.setKeyIdentifier("K0000001");
        return keyData;
    }

    /**
     * Method that returns invalid KeyData object
     * 
     * @return KeyData
     */
    public KeyIdentifierData getKeyIdentifierDataCreateForNotEqual() {

        final KeyIdentifierData keyData = new KeyIdentifierData();
        keyData.setId(1L);
        keyData.setStatus(KeyPairStatus.INACTIVE);
        keyData.setKeyIdentifier("K0000001");
        return keyData;
    }

}
