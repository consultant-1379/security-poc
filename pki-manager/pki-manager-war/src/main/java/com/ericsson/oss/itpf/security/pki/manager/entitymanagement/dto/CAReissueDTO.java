/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto;

import java.io.Serializable;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.ReIssueType;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;

/**
 * Class represents information containing for CA reissue.
 * 
 */
public class CAReissueDTO implements Serializable {

    private static final long serialVersionUID = 1L;

    private String name;
    private boolean rekey;
    private ReIssueType reIssueType;
    private RevocationReason revocationReason;

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name
     *            the name to set
     */
    public void setName(final String name) {
        this.name = name;
    }

    /**
     * @return the rekey
     */
    public boolean isRekey() {
        return rekey;
    }

    /**
     * @param rekey
     *            the rekey to set
     */
    public void setRekey(final boolean rekey) {
        this.rekey = rekey;
    }

    /**
     * @return the reIssueType
     */
    public ReIssueType getReIssueType() {
        return reIssueType;
    }

    /**
     * @param reIssueType
     *            the reIssueType to set
     */
    public void setReIssueType(final ReIssueType reIssueType) {
        this.reIssueType = reIssueType;
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
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + (rekey ? 1231 : 1237);
        result = prime * result + ((reIssueType == null) ? 0 : reIssueType.hashCode());
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
        final CAReissueDTO other = (CAReissueDTO) obj;
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (rekey != other.rekey) {
            return false;
        }
        if (revocationReason != other.revocationReason) {
            return false;
        }
        if (reIssueType != other.reIssueType) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "CAReissueDTO [name=" + name + ", rekey=" + rekey + ", reIssueType=" + reIssueType + ", revocationReason=" + revocationReason + "]";
    }

}
