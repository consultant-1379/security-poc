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

@MappedSuperclass
public abstract class AbstractEntityData implements Serializable {

    private static final long serialVersionUID = -6123102856924874104L;

    @ManyToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "entity_profile_id", nullable = true)
    private EntityProfileData entityProfileData;

    @Column(name = "publishCertificatetoTDPS", nullable = false)
    private boolean publishCertificatetoTDPS;

    @Column(name = "subject_unique_identifier_value", nullable = true)
    private String subjectUniqueIdentifierValue;

    /**
     * @return the entityProfileData
     */
    public EntityProfileData getEntityProfileData() {
        return entityProfileData;
    }

    /**
     * @return the subjectUniqueIdentifierValue
     */
    public String getSubjectUniqueIdentifierValue() {
        return subjectUniqueIdentifierValue;
    }

    /**
     * @param subjectUniqueIdentifierValue the subjectUniqueIdentifierValue to set
     */
    public void setSubjectUniqueIdentifierValue(final String subjectUniqueIdentifierValue) {
        this.subjectUniqueIdentifierValue = subjectUniqueIdentifierValue;
    }



    /**
     * @param entityProfileData
     *            the entityProfileData to set
     */
    public void setEntityProfileData(final EntityProfileData entityProfileData) {
        this.entityProfileData = entityProfileData;
    }

    /**
     * @return the publishCertificatetoTDPS
     */
    public boolean isPublishCertificatetoTDPS() {
        return publishCertificatetoTDPS;
    }

    /**
     * @param publishCertificatetoTDPS
     *            the publishCertificatetoTDPS to set
     */
    public void setPublishCertificatetoTDPS(final boolean publishCertificatetoTDPS) {
        this.publishCertificatetoTDPS = publishCertificatetoTDPS;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "AbstractEntityData [" + (entityProfileData != null ? "entityProfileData=" + entityProfileData + ", " : "") + "publishCertificatetoTDPS=" + publishCertificatetoTDPS + "subjectUniqueIdentifierValue=" + subjectUniqueIdentifierValue + "]";
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
        result = prime * result + ((entityProfileData == null) ? 0 : entityProfileData.hashCode());
        result = prime * result + (publishCertificatetoTDPS ? 1231 : 1237);
        result = prime * result + ((subjectUniqueIdentifierValue == null) ? 0 : subjectUniqueIdentifierValue.hashCode());
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
        final AbstractEntityData other = (AbstractEntityData) obj;
        if (entityProfileData == null) {
            if (other.entityProfileData != null) {
                return false;
            }
        } else if (!entityProfileData.equals(other.entityProfileData)) {
            return false;
        }
        if (publishCertificatetoTDPS != other.publishCertificatetoTDPS) {
            return false;
        }
        if (subjectUniqueIdentifierValue == null) {
            if (other.subjectUniqueIdentifierValue != null) {
                return false;
            }
        } else if (!subjectUniqueIdentifierValue.equals(other.subjectUniqueIdentifierValue)) {
            return false;
        }
        return true;
    }

}
