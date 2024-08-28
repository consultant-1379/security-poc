/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.api;

import java.io.Serializable;
import java.util.List;

import org.bouncycastle.asn1.x509.Attribute;

public interface CredentialManagerSubjectAltName extends Serializable {
    enum ALTERNATE_NAME_TYPE {
        DIRECTORY_NAME, DNS, EMAIL, URI, IP_ADDRESS, OTHER_NAME, REGISTERED_ID, NO_VALUE;
    }

    /**
     * @return the list of the types
     */
    List<ALTERNATE_NAME_TYPE> getType();

    /**
     * @param type
     *            the types list to set
     */
    void setType(List<ALTERNATE_NAME_TYPE> type);

    /**
     * @return the list values for each type
     */
    List<List<String>> getValue();

    /**
     * @param value
     *            the list of values to set
     */
    void setValue(List<List<String>> value);

    Attribute getAttribute();

    String getSubjectAlternativeName();

}