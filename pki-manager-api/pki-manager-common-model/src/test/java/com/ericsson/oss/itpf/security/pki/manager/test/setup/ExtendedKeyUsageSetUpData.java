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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;

/**
 * This class acts as builder for {@link ExtendedKeyUsageSetUpData}
 */
public class ExtendedKeyUsageSetUpData {
    /**
     * Method that returns valid ExtendedKeyUsage
     * 
     * @return OtherName
     */
    public ExtendedKeyUsage getExtendedKeyUsageForEqual() {
        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        final List<KeyPurposeId> keyPurposeIdList = new ArrayList<KeyPurposeId>();
        keyPurposeIdList.add(KeyPurposeId.ANY_EXTENDED_KEY_USAGE);
        keyPurposeIdList.add(KeyPurposeId.ID_KP_CLIENT_AUTH);
        keyPurposeIdList.add(KeyPurposeId.ID_KP_CODE_SIGNING);
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIdList);
        extendedKeyUsage.setCritical(true);
        return extendedKeyUsage;

    }

    /**
     * Method that returns different valid ExtendedKeyUsage
     * 
     * @return OtherName
     */
    public ExtendedKeyUsage getExtendedKeyUsageForNotEqual() {
        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        final List<KeyPurposeId> keyPurposeIdList = new ArrayList<KeyPurposeId>();
        keyPurposeIdList.add(KeyPurposeId.ID_KP_TIME_STAMPING);
        keyPurposeIdList.add(KeyPurposeId.ID_KP_SERVER_AUTH);
        keyPurposeIdList.add(KeyPurposeId.ID_KP_OCSP_SIGNING);
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIdList);
        extendedKeyUsage.setCritical(false);
        return extendedKeyUsage;

    }

}
