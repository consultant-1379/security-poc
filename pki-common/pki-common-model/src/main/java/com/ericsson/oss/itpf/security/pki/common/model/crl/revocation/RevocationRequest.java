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
package com.ericsson.oss.itpf.security.pki.common.model.crl.revocation;

import java.io.Serializable;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.entryextension.CrlEntryExtensions;

/**
 * This class contains all the attributes that are used to raise a revocation request.
 * 
 * @author xvenkat
 *
 */

public class RevocationRequest implements Serializable {

    private static final long serialVersionUID = 5623723046478442583L;

    private EntityInfo entity;

    private CertificateAuthority caEntity;

    private List<Certificate> certificatesToBeRevoked;

    private CrlEntryExtensions crlEntryExtensions;

    /**
     * @return the entity
     */
    public EntityInfo getEntity() {
        return entity;
    }

    /**
     * @param entity
     *            the entity to set
     */
    public void setEntity(final EntityInfo entity) {
        this.entity = entity;
    }

    /**
     * @return the caEntity
     */
    public CertificateAuthority getCaEntity() {
        return caEntity;
    }

    /**
     * @param caEntity
     *            the caEntity to set
     */
    public void setCaEntity(final CertificateAuthority caEntity) {
        this.caEntity = caEntity;
    }

    /**
     * @return the certificatesToBeRevoked
     */
    public List<Certificate> getCertificatesToBeRevoked() {
        return certificatesToBeRevoked;
    }

    /**
     * @param certificatesToBeRevoked
     *            the certificatesToBeRevoked to set
     */
    public void setCertificatesToBeRevoked(final List<Certificate> certificatesToBeRevoked) {
        this.certificatesToBeRevoked = certificatesToBeRevoked;
    }

    /**
     * @return the crlEntryExtensions
     */
    public CrlEntryExtensions getCrlEntryExtensions() {
        return crlEntryExtensions;
    }

    /**
     * @param crlEntryExtensions
     *            the crlEntryExtensions to set
     */
    public void setCrlEntryExtensions(final CrlEntryExtensions crlEntryExtensions) {
        this.crlEntryExtensions = crlEntryExtensions;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((caEntity == null) ? 0 : caEntity.hashCode());
        result = prime * result + ((certificatesToBeRevoked == null) ? 0 : certificatesToBeRevoked.hashCode());
        result = prime * result + ((crlEntryExtensions == null) ? 0 : crlEntryExtensions.hashCode());
        result = prime * result + ((entity == null) ? 0 : entity.hashCode());
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
        
        final RevocationRequest other = (RevocationRequest) obj;
        if (caEntity == null) {
            if (other.caEntity != null) {
                return false;
            }
        } else if (!caEntity.equals(other.caEntity)) {
            return false;
        }
        
        if (certificatesToBeRevoked == null) {
            if (other.certificatesToBeRevoked != null) {
                return false;
            }
        } else if (!certificatesToBeRevoked.equals(other.certificatesToBeRevoked)) {
            return false;
        }
        
        if (crlEntryExtensions == null) {
            if (other.crlEntryExtensions != null) {
                return false;
            }
        } else if (!crlEntryExtensions.equals(other.crlEntryExtensions)) {
            return false;
        }
        
        if (entity == null) {
            if (other.entity != null) {
                return false;
            }
        } else if (!entity.equals(other.entity)) {
            return false;
        }
        
        return true;
    }

    @Override
    public String toString() {
        return "RevocationRequest [entity=" + entity + ", caEntity=" + caEntity + ", certificatesToBeRevoked=" + certificatesToBeRevoked + ", crlEntryExtensions=" + crlEntryExtensions + "]";
    }

}
