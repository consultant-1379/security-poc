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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps;

import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * This class is a notification class which assembles all the data required to fire an Certificate event to pki-ra-
 * 
 * @author tcsdemi
 *
 */
public class CertificateEventInfo {
    private String entityName;
    private List<Certificate> certificates;
    private EntityType entityType;
    private TDPSPublishStatusType publishType;

    /**
     * sets EntityName which is in the PKI Manager Entity table.
     * 
     * @param entityName
     */
    public void setEntityName(final String entityName) {
        this.entityName = entityName;
    }

    /**
     * sets entityType as either CA_Entity or ENTITY
     * 
     * @param entityType
     */
    public void setEntityType(final EntityType entityType) {
        this.entityType = entityType;
    }

    /**
     * sets publish status type as either PUBLISH or UNPUBLISH
     * 
     * @param publishType
     */
    public void setPublishType(final TDPSPublishStatusType publishType) {
        this.publishType = publishType;
    }

    public String getEntityName() {
        return entityName;
    }

    public EntityType getEntityType() {
        return entityType;
    }

    public TDPSPublishStatusType getPublishType() {
        return publishType;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }

    public void setCertificates(final List<Certificate> certificates) {
        this.certificates = certificates;
    }

    @Override
    public String toString() {
        return "CertificateEventInfo [entityName=" + entityName + ",entityType=" + entityType.getValue() + ",publishType=" + publishType.getValue() + "]";
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

        final CertificateEventInfo other = (CertificateEventInfo) obj;

        if (this.getEntityName() == null) {
            if (other.getEntityName() != null) {
                return false;
            }
        } else if (!this.getEntityName().equals(other.getEntityName())) {
            return false;
        }

        if (this.getEntityType() == null) {
            if (other.getEntityType() != null) {
                return false;
            }
        } else if (!this.getEntityType().equals(other.getEntityType())) {
            return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((entityName == null) ? 0 : entityName.hashCode());
        result = prime * result + ((entityType == null) ? 0 : entityType.hashCode());
        return result;
    }

}