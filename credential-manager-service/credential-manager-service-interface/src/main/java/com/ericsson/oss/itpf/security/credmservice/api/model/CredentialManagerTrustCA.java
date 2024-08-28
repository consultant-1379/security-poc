/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
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

public class CredentialManagerTrustCA implements Serializable {

    private static final long serialVersionUID = -5831738172942807162L;

    private String trustCAName;

    private boolean isChainRequired;

    public CredentialManagerTrustCA(final String trustCAName, final boolean isChainRequired) {
        this.trustCAName = trustCAName;
        this.isChainRequired = isChainRequired;
    }

    public String getTrustCAName() {
        return trustCAName;
    }

    public void setTrustCAName(final String trustCAName) {
        this.trustCAName = trustCAName;
    }

    public boolean isChainRequired() {
        return isChainRequired;
    }

    public void setChainRequired(final boolean isChainRequired) {
        this.isChainRequired = isChainRequired;
    }

    @Override
    public String toString() {
        return "CredentialManagerTrustCA [trustCAName=" + trustCAName
                + ", isChainRequired=" + isChainRequired + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (isChainRequired ? 1231 : 1237);
        result = prime * result + ((trustCAName == null) ? 0 : trustCAName.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        final CredentialManagerTrustCA other = (CredentialManagerTrustCA) obj;
        if (isChainRequired != other.isChainRequired)
            return false;
        if (trustCAName == null) {
            if (other.trustCAName != null)
                return false;
        } else if (!trustCAName.equals(other.trustCAName))
            return false;
        return true;
    }
}
