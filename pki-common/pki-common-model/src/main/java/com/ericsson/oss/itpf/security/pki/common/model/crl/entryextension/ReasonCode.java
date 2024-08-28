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
package com.ericsson.oss.itpf.security.pki.common.model.crl.entryextension;

import java.io.Serializable;

import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class ReasonCode implements Serializable {

    private static final long serialVersionUID = -6323793245599912703L;

    // As per the RFC critical flag is always false for ReasonCode. Hence making it final
    private static final boolean critical = false;

    private RevocationReason revocationReason;

    /**
     * @return the critical
     */
    public boolean isCritical() {
        return critical;
    }

    /**
     * @return the revocationReason
     */
    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

    /**
     * @param revocationReason
     *            the revocationReason to set
     */
    public void setRevocationReason(final RevocationReason revocationReason) {
        this.revocationReason = revocationReason;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (critical ? 1231 : 1237);
        result = prime * result + ((revocationReason == null) ? 0 : revocationReason.hashCode());
        return result;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj == null) {
            return false;
        }

        if (getClass() != obj.getClass()) {
            return false;
        }

        final ReasonCode other = (ReasonCode) obj;
        if (critical != other.critical) {
            return false;
        }

        if (revocationReason != other.revocationReason) {
            return false;
        }

        return true;
    }

    @Override
    public String toString() {
        return "ReasonCode [critical=" + critical + ", revocationReason=" + revocationReason + "]";
    }

}
