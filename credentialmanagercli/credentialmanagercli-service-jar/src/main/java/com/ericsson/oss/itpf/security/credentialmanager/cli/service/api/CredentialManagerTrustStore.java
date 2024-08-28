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

public interface CredentialManagerTrustStore extends Serializable {

    /**
     * @return the tsType
     */
    String getType();

    /**
     * @return the location
     */
    String getLocation();

    /**
     * @return the password
     */
    String getPassword();

    /**
     * 
     * @return true if TrustStore already exists or false otherwise
     */
    boolean exists();

    /**
     * @return
     */
    String getFolder();

    /**
     * @return
     */
    String getAlias();

    /**
     * @return
     */
    String getSource();

}
