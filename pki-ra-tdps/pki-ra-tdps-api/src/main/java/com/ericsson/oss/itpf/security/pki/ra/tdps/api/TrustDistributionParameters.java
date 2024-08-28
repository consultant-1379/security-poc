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
package com.ericsson.oss.itpf.security.pki.ra.tdps.api;

/**
 * This class contains all parameters required to download a certificate from Trust distribution service
 * 
 * @author tcsdemi
 *
 */
public class TrustDistributionParameters {

    private String entityType;
    private String entityName;
    private String issuerName;
    private String certificateSerialId;
    private String certificateStatus;

    /**
     * @return the entityType
     */
    public String getEntityType() {
        return entityType;
    }

    /**
     * @param entityType
     *            the entityType to set
     */
    public TrustDistributionParameters setEntityType(final String entityType) {
        this.entityType = entityType;
        return this;
    }

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
    public TrustDistributionParameters setEntityName(final String entityName) {
        this.entityName = entityName;
        return this;
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
    public TrustDistributionParameters setIssuerName(final String issuerName) {
        this.issuerName = issuerName;
        return this;
    }

    /**
     * @return the certificateSerialId
     */
    public String getCertificateSerialId() {
        return certificateSerialId;
    }

    /**
     * @param certificateSerialId
     *            the certificateSerialId to set
     */
    public TrustDistributionParameters setCertificateSerialId(final String certificateSerialId) {
        this.certificateSerialId = certificateSerialId;
        return this;
    }

    /**
     * @return the certificateStatus
     */
    public String getCertificateStatus() {
        return certificateStatus;
    }

    /**
     * @param certificateStatus
     *            the certificateStatus to set
     */
    public TrustDistributionParameters setCertificateStatus(final String certificateStatus) {
        this.certificateStatus = certificateStatus;
        return this;
    }

    /**
     * Returns string representation of {@link TDPSEntityData} object.
     */
    @Override
    public String toString() {
       return "For EntityName: " + this.entityName + " of entity type: " + this.entityType + " having " + this.certificateStatus + " certificate with serial Id as "
                + this.certificateSerialId + " issued by CA " + this.issuerName;


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
        final TrustDistributionParameters other = (TrustDistributionParameters) obj;
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

        if (certificateSerialId == null) {
            if (other.certificateSerialId != null) {
                return false;
            }
        } else if (!certificateSerialId.equals(other.certificateSerialId)) {
            return false;
        }

        if (certificateStatus == null) {
            if (other.certificateStatus != null) {
                return false;
            }
        } else if (!certificateStatus.equals(other.certificateStatus)) {
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
     * Returns the hash code of object.
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((entityName == null) ? 0 : entityName.hashCode());
        result = prime * result + ((entityType == null) ? 0 : entityType.hashCode());
        result = prime * result + ((certificateStatus == null) ? 0 : certificateStatus.hashCode());
        result = prime * result + ((certificateSerialId == null) ? 0 : issuerName.hashCode());
        result = prime * result + ((issuerName == null) ? 0 : issuerName.hashCode());

        return result;
    }

}
