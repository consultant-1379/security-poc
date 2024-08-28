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

import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;

import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequestStatus;

/**
 * Represents revocation jpa entity to manage storage of revocation request
 */
@Entity
@Table(name = "Revocation_Request")
public class RevocationRequestData {

    @Id
    @SequenceGenerator(name = "SEQ_REVOCATION_REQUEST_ID_GENERATOR", sequenceName = "SEQ_REVOCATION_REQUEST_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_REVOCATION_REQUEST_ID_GENERATOR")
    @Column(name = "id")
    private long id;

    @ManyToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "entity_id", referencedColumnName = "id", nullable = true)
    private EntityData entity;

    @ManyToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "ca_entity_id", referencedColumnName = "id", nullable = true)
    private CAEntityData caEntity;

    //JSON String
    @Column(name = "crl_entry_extensions", columnDefinition = "TEXT")
    private String crlEntryExtensionsJSONData;

    @Column(name = "status", nullable = false)
    private RevocationRequestStatus status;

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.MERGE, CascadeType.PERSIST })
    @JoinTable(name = "REVOCATION_REQUEST_CERTIFICATE", joinColumns = @JoinColumn(name = "revocation_id"), inverseJoinColumns = @JoinColumn(name = "certificate_id"))
    private Set<CertificateData> certificatesToRevoke = new HashSet<CertificateData>();

    /**
     * @return the entityId
     */
    public EntityData getEntity() {
        return entity;
    }

    /**
     * @param entityId
     *            the entityId to set
     */
    public void setEntity(final EntityData entity) {
        this.entity = entity;
    }

    /**
     * @return the issuerId
     */
    public CAEntityData getCaEntity() {
        return caEntity;
    }

    /**
     * @param issuerId
     *            the issuerId to set
     */
    public void setCaEntity(final CAEntityData caEntity) {
        this.caEntity = caEntity;
    }

    /**
     * @return the crlEntryExtensionsJSONData
     */
    public String getCrlEntryExtensionsJSONData() {
        return crlEntryExtensionsJSONData;
    }

    /**
     * @param crlEntryExtensionsJSONData
     *            the crlEntryExtensionsJSONData to set
     */
    public void setCrlEntryExtensionsJSONData(final String crlEntryExtensionsJSONData) {
        this.crlEntryExtensionsJSONData = crlEntryExtensionsJSONData;
    }

    /**
     * @return the status
     */
    public RevocationRequestStatus getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final RevocationRequestStatus status) {
        this.status = status;
    }

    /**
     * @return the id
     */
    public long getId() {
        return id;
    }

    /**
     * @param id
     *            the id to set
     */
    public void setId(final long id) {
        this.id = id;
    }

    /**
     * @return the revocationData
     */
    public Set<CertificateData> getCertificatesToRevoke() {
        return certificatesToRevoke;
    }

    /**
     * @param revocationData
     *            the revocationData to set
     */
    public void setCertificatesToRevoke(final Set<CertificateData> revocationData) {
        this.certificatesToRevoke = revocationData;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((caEntity == null) ? 0 : caEntity.hashCode());
        result = prime * result + ((certificatesToRevoke == null) ? 0 : certificatesToRevoke.hashCode());
        result = prime * result + ((crlEntryExtensionsJSONData == null) ? 0 : crlEntryExtensionsJSONData.hashCode());
        result = prime * result + ((entity == null) ? 0 : entity.hashCode());
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((status == null) ? 0 : status.hashCode());
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
        
        final RevocationRequestData other = (RevocationRequestData) obj;
        if (caEntity == null) {
            if (other.caEntity != null) {
                return false;
            }
        } else if (!caEntity.equals(other.caEntity)) {
            return false;
        }
        
        if (certificatesToRevoke == null) {
            if (other.certificatesToRevoke != null) {
                return false;
            }
        } else if (!certificatesToRevoke.equals(other.certificatesToRevoke)) {
            return false;
        }
        
        if (crlEntryExtensionsJSONData == null) {
            if (other.crlEntryExtensionsJSONData != null) {
                return false;
            }
        } else if (!crlEntryExtensionsJSONData.equals(other.crlEntryExtensionsJSONData)) {
            return false;
        }
        
        if (entity == null) {
            if (other.entity != null) {
                return false;
            }
        } else if (!entity.equals(other.entity)) {
            return false;
        }
        
        if (id != other.id) {
            return false;
        }
        
        if (status != other.status) {
            return false;
        }
        
        return true;
    }

    @Override
    public String toString() {
        return "RevocationRequestData [id=" + id + ", entity=" + entity + ", caEntity=" + caEntity + ", crlEntryExtensionsJSONData=" + crlEntryExtensionsJSONData + ", status=" + status
                + ", certificatesToRevoke=" + certificatesToRevoke + "]";
    }

}
