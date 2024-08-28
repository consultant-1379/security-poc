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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessDescription;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessMethod;

/**
 * This class acts as builder for {@link AlgorithmSetUpData}
 */
public class AccessDescriptionSetUpData {

    private static final String EQUAL_ACCESS_LOCATION = "INDIA";
    private static final String NOT_EQUAL_ACCESS_LOCATION = "IRELAND";

    /**
     * Method that returns valid AccessDescription
     * 
     * @return AccessDescription
     */
    public AccessDescription getAccessDescriptionForEqual() {
        final AccessDescription accessDescription = new AccessDescription();
        accessDescription.setAccessLocation(EQUAL_ACCESS_LOCATION);
        accessDescription.setAccessMethod(AccessMethod.CA_ISSUER);
        return accessDescription;
    }

    /**
     * Method that returns different valid AccessDescription
     * 
     * @return AccessDescription
     */
    public AccessDescription getAccessDescriptionForNotEqual() {
        final AccessDescription accessDescription = new AccessDescription();
        accessDescription.setAccessLocation(NOT_EQUAL_ACCESS_LOCATION);
        accessDescription.setAccessMethod(AccessMethod.OCSP);
        return accessDescription;
    }

}
