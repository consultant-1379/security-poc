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

package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class CredentialManagerCrlMaps implements Serializable {

    private static final long serialVersionUID = 1L;

    private final Map<String, CredentialManagerX509CRL> internalCACrlMap;

    private final Map<String, CredentialManagerX509CRL> externalCACrlMap;

    /**
     * 
     */
    public CredentialManagerCrlMaps() {

        this.internalCACrlMap = new HashMap<String, CredentialManagerX509CRL>();
        this.externalCACrlMap = new HashMap<String, CredentialManagerX509CRL>();

    }

    /**
     * @return the internalCACrlMap
     */
    public Map<String, CredentialManagerX509CRL> getInternalCACrlMap() {
        return internalCACrlMap;
    }

    /**
     * @param internalCACrlMap
     *            the internalCACrlMap to set
     */
    //    public void setInternalCACrlMap(final Map<String, CredentialManagerX509CRL> internalCACrlMap) {
    //        this.internalCACrlMap = internalCACrlMap;
    //    }

    /**
     * @return the externalCACrlMap
     */
    public Map<String, CredentialManagerX509CRL> getExternalCACrlMap() {
        return externalCACrlMap;
    }

    /**
     * @param externalCACrlMap
     *            the externalCACrlMap to set
     */
    //    public void setExternalCACrlMap(final Map<String, CredentialManagerX509CRL> externalCACrlMap) {
    //        this.externalCACrlMap = externalCACrlMap;
    //    }

}
