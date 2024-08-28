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
 *----------------------------------------------------------------------------**/
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity;

import java.io.Serializable;
import java.util.Arrays;

import javax.persistence.*;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity;

/**
 * This is JPA entity which is used to store certificates for entities. It consist of:
 * <p>
 * entityName- Common name of the entity. Can be repeated across entity types but must be unique for a particular entityType.
 * <p>
 * entityType- Entity can be CA or Entity.
 * <p>
 * certificate- Actual Active certificate of the entity in PKI system. It is stored as a byte Array in DB
 * <p>
 * serialNo-Certificate serialNumber stored as String
 * <p>
 * 
 * @author tcsdemi
 *
 */
@Entity
@Table(name = "TDPSData")
@NamedQueries({ @NamedQuery(name = "TDPSEntityData.findByEntityNameAndEntityType", query = "SELECT t FROM TDPSEntityData t WHERE t.entityName = :entityName AND t.entityType = :entityType AND t.serialNo = :serialNo AND t.tdpsCertificateStatus = :tdpsCertificateStatus AND t.issuerName = :issuerName") ,@NamedQuery(name = "TDPSEntityData.findByEntityNameAndType", query = "SELECT t FROM TDPSEntityData t WHERE t.entityName = :entityName AND t.entityType = :entityType AND t.serialNo = :serialNo AND t.issuerName = :issuerName")})
public class TDPSEntityData implements Serializable {

    private static final long serialVersionUID = 716454044271545215L;

    @Id
    @SequenceGenerator(name = "SEQ_TDPS_ID_GENERATOR", sequenceName = "SEQ_TDPS_ID_GENERATOR", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_TDPS_ID_GENERATOR")
    @Column(name = "id")
    private long id;

    @Column(name = "entity_name", nullable = false)
    private String entityName;

    @Column(name = "entity_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private TDPSEntity entityType;

    @Column(name = "certificate", nullable = false)
    private byte[] certificate;

    @Column(name = "serial_no", nullable = false)
    private String serialNo;

    @Column(name = "issuer_name", nullable = false)
    private String issuerName;

    @Column(name = "status", nullable = false)
    @Enumerated(EnumType.STRING)
    private TDPSCertificateStatus tdpsCertificateStatus;

    public TDPSEntity getEntityType() {
        return entityType;
    }

    public void setEntityType(final TDPSEntity entityType) {
        this.entityType = entityType;
    }

    /**
     * @return the issuerName
     */
    public String getIssuerName() {
        return issuerName;
    }

    /**
     * @param issuerName
     *            the issuerName to set
     */
    public void setIssuerName(final String issuerName) {
        this.issuerName = issuerName;
    }

    /**
     * @return the tdpsCertificateStatus
     */
    public TDPSCertificateStatus getTdpsCertificateStatus() {
        return tdpsCertificateStatus;
    }

    /**
     * @param tdpsCertificateStatus
     *            the tdpsCertificateStatus to set
     */
    public void setTdpsCertificateStatus(final TDPSCertificateStatus tdpsCertificateStatus) {
        this.tdpsCertificateStatus = tdpsCertificateStatus;
    }

    /**
     * Gets the serial number
     * 
     * @return
     */
    public String getSerialNo() {
        return serialNo;
    }

    /**
     * Sets the certificate serial No
     * 
     * @param serialNo
     */
    public void setSerialNo(final String serialNo) {
        this.serialNo = serialNo;
    }

    /**
     * Get the entity Name
     * 
     * @return
     */
    public String getEntityName() {
        return entityName;
    }

    /**
     * Sets the name of the entity. Usually this is the entityName which is sent from Manager.
     * 
     * @param entityName
     */
    public void setEntityName(final String entityName) {
        this.entityName = entityName;
    }

    /**
     * Get the PEM encoded format of the certificate
     * 
     * @return
     */
    public byte[] getCertificate() {
        return certificate;
    }

    /**
     * Set the PEM encoded format of the certificate
     * 
     * @param certificate
     */
    public void setCertificate(final byte[] certificate) {
        this.certificate = certificate;
    }

    /**
     * Returns the hash code of object.
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((entityName == null) ? 0 : entityName.hashCode());
        result = prime * result + ((entityType == null) ? 0 : entityType.hashCode());
        result = prime * result + ((serialNo == null) ? 0 : serialNo.hashCode());
        result = prime * result + ((issuerName == null) ? 0 : issuerName.hashCode());
        result = prime * result + Arrays.hashCode(certificate);

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
        final TDPSEntityData other = (TDPSEntityData) obj;
        if (!Arrays.equals(certificate, other.certificate)) {
            return false;
        }
        if (id != other.id) {
            return false;
        }
        if (entityName == null) {
            if (other.entityName != null) {
                return false;
            }
        } else if (!entityName.equals(other.entityName)) {
            return false;
        }
        if (entityType == null) {
            if (other.entityType != null) {
                return false;
            }
        } else if (!entityType.equals(other.entityType)) {
            return false;
        }
        if (serialNo == null) {
            if (other.serialNo != null) {
                return false;
            }
        } else if (!serialNo.equals(other.serialNo)) {
            return false;
        }
        if (issuerName == null) {
            if (other.issuerName != null) {
                return false;
            }
        } else if (!issuerName.equals(other.issuerName)) {
            return false;
        }
        return true;
    }

    /**
     * Returns string representation of {@link TDPSEntityData} object.
     */
    @Override
    public String toString() {
        return "TDPSEntityData [id=" + id + ", certificate=" + Arrays.toString(certificate) + "]" + (entityName != null ? "entityName=" + entityName + ", " : "")
                + (entityType != null ? "entityType=" + entityType.toString() + ", " : "") + (serialNo != null ? "serialNo=" + serialNo + ", " : "")
                + (issuerName != null ? "issuerName=" + issuerName + ", " : "") + "]";
    }

}