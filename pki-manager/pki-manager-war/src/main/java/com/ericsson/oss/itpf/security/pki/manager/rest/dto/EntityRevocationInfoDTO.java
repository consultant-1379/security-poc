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
package com.ericsson.oss.itpf.security.pki.manager.rest.dto;

import java.io.Serializable;

import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;

/**
 * This EntityRevocationInfoDTO object has information which is used to revoke the valid Entity Certificates.
 * 
 * @author xnarsir
 */
public class EntityRevocationInfoDTO implements Serializable {

    private static final long serialVersionUID = 1L;
    private String entityName;
    private RevocationReason revocationReason;

    /**
     * @return the entityName
     */
    public String getEntityName() {
        return entityName;
    }

    /**
     * @param entityName
     *            the entityName to set
     */
    public void setEntityName(final String entityName) {
        this.entityName = entityName;
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

    /**
     * Returns the has code of object.
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((entityName == null) ? 0 : entityName.hashCode());
        result = prime * result + ((revocationReason == null) ? 0 : revocationReason.hashCode());
        return result;
    }

    /**
     * Indicates whether the invoking object is "equal to" the parameterized object
     */
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
        final EntityRevocationInfoDTO other = (EntityRevocationInfoDTO) obj;
        if (entityName == null) {
            if (other.entityName != null) {
                return false;
            }
        } else if (!entityName.equals(other.entityName)) {
            return false;
        }
        if (revocationReason != other.revocationReason) {
            return false;
        }
        return true;
    }

    /**
     * Returns string representation of {@link EntityRevocationInfoDTO} object.
     */
    @Override
    public String toString() {
        return "EntityRevocationInfoDTO [entityName=" + entityName + ", revocationReason=" + revocationReason + "]";
    }

}
