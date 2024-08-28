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

import javax.persistence.Embeddable;
import javax.persistence.ManyToOne;

@Embeddable
public class TrustCAChainId implements Serializable {
    /**
	 * 
	 */
    private static final long serialVersionUID = 7127890772772243102L;

    @ManyToOne
    private TrustProfileData trustProfileData;
    @ManyToOne
    private CAEntityData caEntityData;

    /**
     * @return the trustProfileData
     */
    public TrustProfileData getTrustProfileData() {
        return trustProfileData;
    }

    /**
     * @param trustProfileData
     *            the trustProfileData to set
     */
    public void setTrustProfileData(final TrustProfileData trustProfileData) {
        this.trustProfileData = trustProfileData;
    }

    /**
     * @return the caEntityData
     */
    public CAEntityData getCaEntityData() {
        return caEntityData;
    }

    /**
     * @param caEntityData
     *            the caEntityData to set
     */
    public void setCaEntityData(final CAEntityData caEntityData) {
        this.caEntityData = caEntityData;
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
        result = prime * result + ((caEntityData == null) ? 0 : caEntityData.hashCode());
        result = prime * result + ((trustProfileData == null) ? 0 : trustProfileData.hashCode());
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
        final TrustCAChainId other = (TrustCAChainId) obj;
        if (caEntityData == null) {
            if (other.caEntityData != null) {
                return false;
            }
        } else if (!caEntityData.equals(other.caEntityData)) {
            return false;
        }
        if (trustProfileData == null) {
            if (other.trustProfileData != null) {
                return false;
            }
        } else if (!trustProfileData.equals(other.trustProfileData)) {
            return false;
        }
        return true;
    }
}
