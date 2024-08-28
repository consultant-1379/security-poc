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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;

/**
 * This class acts as builder for {@link KeyUsageSetUpData}
 */
public class KeyUsageSetUpData {
    /**
     * Method that returns valid KeyUsage
     * 
     * @return KeyUsage
     */
    public KeyUsage getKeyUsageForEqual() {
        final KeyUsage keyUsage = new KeyUsage();
        keyUsage.setCritical(true);
        final List<KeyUsageType> supportedKeyUsageTypes = new ArrayList<KeyUsageType>();
        supportedKeyUsageTypes.add(KeyUsageType.CRL_SIGN);
        supportedKeyUsageTypes.add(KeyUsageType.DATA_ENCIPHERMENT);
        keyUsage.setSupportedKeyUsageTypes(supportedKeyUsageTypes);
        return keyUsage;
    }

    /**
     * Method that returns different valid KeyUsage
     * 
     * @return KeyUsage
     */
    public KeyUsage getKeyUsageForNotEqual() {
        final KeyUsage keyUsage = new KeyUsage();
        keyUsage.setCritical(false);
        final List<KeyUsageType> supportedKeyUsageTypes = new ArrayList<KeyUsageType>();
        supportedKeyUsageTypes.add(KeyUsageType.KEY_AGREEMENT);
        supportedKeyUsageTypes.add(KeyUsageType.ENCIPHER_ONLY);
        supportedKeyUsageTypes.add(KeyUsageType.DECIPHER_ONLY);
        keyUsage.setSupportedKeyUsageTypes(supportedKeyUsageTypes);
        return keyUsage;
    }
}
