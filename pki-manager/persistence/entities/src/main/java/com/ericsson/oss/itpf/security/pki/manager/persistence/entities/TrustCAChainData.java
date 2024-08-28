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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import java.io.Serializable;

import javax.persistence.*;

@Entity
@Table(name = "TrustCAChain")
@AssociationOverrides({ @AssociationOverride(name = "trustChainId.trustProfileData", joinColumns = @JoinColumn(name = "trustprofile_id")),
        @AssociationOverride(name = "trustChainId.caEntityData", joinColumns = @JoinColumn(name = "caentity_id")) })
public class TrustCAChainData implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = -8667047841186369456L;

    @EmbeddedId
    private TrustCAChainId trustChainId = new TrustCAChainId();

    @Column(name = "is_chain_required", nullable = false)
    private boolean isChainRequired;

    public TrustProfileData getTrustProfile() {
        return getTrustChainId().getTrustProfileData();
    }

    public void setTrustProfile(final TrustProfileData trustProfileData) {
        getTrustChainId().setTrustProfileData(trustProfileData);
    }

    public CAEntityData getCAEntity() {
        return getTrustChainId().getCaEntityData();
    }

    public void setCAEntity(final CAEntityData caEntityData) {
        getTrustChainId().setCaEntityData(caEntityData);
    }

    /**
     * @return the trustChainId
     */
    public TrustCAChainId getTrustChainId() {
        return trustChainId;
    }

    /**
     * @param trustChainId
     *            the trustChainId to set
     */
    public void setTrustChainId(final TrustCAChainId trustChainId) {
        this.trustChainId = trustChainId;
    }

    /**
     * @return the isChainRequired
     */
    public boolean isChainRequired() {
        return isChainRequired;
    }

    /**
     * @param isChainRequired
     *            the isChainRequired to set
     */
    public void setChainRequired(final boolean isChainRequired) {
        this.isChainRequired = isChainRequired;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "TrustCAChainData [" + (trustChainId != null ? "trustChainId=" + trustChainId + ", " : "") + "isChainRequired=" + isChainRequired + "]";
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (isChainRequired ? 1231 : 1237);
        result = prime * result + ((trustChainId == null) ? 0 : trustChainId.hashCode());
        return result;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
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
        final TrustCAChainData other = (TrustCAChainData) obj;
        if (isChainRequired != other.isChainRequired) {
            return false;
        }
        if (trustChainId == null) {
            if (other.trustChainId != null) {
                return false;
            }
        } else if (!trustChainId.equals(other.trustChainId)) {
            return false;
        }
        return true;
    }

}
