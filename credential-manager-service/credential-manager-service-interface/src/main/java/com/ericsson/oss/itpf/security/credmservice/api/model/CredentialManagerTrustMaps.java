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

public class CredentialManagerTrustMaps implements Serializable {

    private static final long serialVersionUID = 1L;

    private Map<String, CredentialManagerCertificateAuthority> internalCATrustMap;

    private Map<String, CredentialManagerCertificateAuthority> externalCATrustMap;

    /**
     * 
     */
    public CredentialManagerTrustMaps() {

        this.internalCATrustMap = new HashMap<String, CredentialManagerCertificateAuthority>();
        this.externalCATrustMap = new HashMap<String, CredentialManagerCertificateAuthority>();

    }

    /**
     * @return the internalCATrustMap
     */
    public Map<String, CredentialManagerCertificateAuthority> getInternalCATrustMap() {
        return this.internalCATrustMap;
    }

    /**
     * @param internalCATrustMap
     *            the internalCATrustMap to set
     */
    public void setInternalCATrustMap(final Map<String, CredentialManagerCertificateAuthority> internalCATrustMap) {
        this.internalCATrustMap = internalCATrustMap;
    }

    /**
     * @return the externalCATrustMap
     */
    public Map<String, CredentialManagerCertificateAuthority> getExternalCATrustMap() {
        return this.externalCATrustMap;
    }

    /**
     * @param externalCATrustMap
     *            the externalCATrustMap to set
     */
    public void setExternalCATrustMap(final Map<String, CredentialManagerCertificateAuthority> externalCATrustMap) {
        this.externalCATrustMap = externalCATrustMap;
    }

}
