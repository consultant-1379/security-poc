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
package com.ericsson.oss.itpf.security.pki.manager.model;

import java.io.Serializable;
import java.security.cert.X509Certificate;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;

/**
 * This class contains all the information needed for TrustDistributionURL like entityName,Type,certificateSerialNumber,
 * subjectDN,IssuerDN,IssuerFullDN,certificateStatus,trustdistributionPointURL,ipv4Address and ipv6Address
 *
 * @author tcsdemi
 *
 */
public class TrustedEntityInfo implements Serializable {

    private static final long serialVersionUID = 2650317279556631155L;

    private String entityName;
    private EntityType entityType;
    private String certificateSerialNumber;
    private String subjectDN;
    private String issuerDN;
    private String issuerFullDN;
    private CertificateStatus certificateStatus;
    private String trustDistributionPointURL;
    private String ipv4TrustDistributionPointURL;
    private String ipv6TrustDistributionPointURL;
    private X509Certificate x509Certificate;

    /**
     * @return the x509Certificate
     */
    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    /**
     * @param x509Certificate
     *            the x509Certificate to set
     */
    public void setX509Certificate(final X509Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
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
    public void setEntityName(final String entityName) {
        this.entityName = entityName;
    }

    /**
     * @return the entityType
     */
    public EntityType getEntityType() {
        return entityType;
    }

    /**
     * @param entityType
     *            the entityType to set
     */
    public void setEntityType(final EntityType entityType) {
        this.entityType = entityType;
    }

    /**
     * @return the certificateSerialNumber
     */
    public String getCertificateSerialNumber() {
        return certificateSerialNumber;
    }

    /**
     * @param certificateSerialNumber
     *            the certificateSerialNumber to set
     */
    public void setCertificateSerialNumber(final String certificateSerialNumber) {
        this.certificateSerialNumber = certificateSerialNumber;
    }

    /**
     * @return the subjectDN
     */
    public String getSubjectDN() {
        return subjectDN;
    }

    /**
     * @param subjectDN
     *            the subjectDN to set
     */
    public void setSubjectDN(final String subjectDN) {
        this.subjectDN = subjectDN;
    }

    /**
     * @return the issuerDN
     */
    public String getIssuerDN() {
        return issuerDN;
    }

    /**
     * @param issuerDN
     *            the issuerDN to set
     */
    public void setIssuerDN(final String issuerDN) {
        this.issuerDN = issuerDN;
    }

    /**
     * @return the issuerFullDN
     */

    public String getIssuerFullDN() {
        return issuerFullDN;
    }

    /**
     * @param issuerFullDN
     *            the issuer full DN to set
     */
    public void setIssuerFullDN(final String issuerFullDN) {
        this.issuerFullDN = issuerFullDN;
    }

    /**
     * @return the certificateStatus
     */
    public CertificateStatus getCertificateStatus() {
        return certificateStatus;
    }

    /**
     * @param certificateStatus
     *            the certificateStatus to set
     */
    public void setCertificateStatus(final CertificateStatus certificateStatus) {
        this.certificateStatus = certificateStatus;
    }

    /**
     * @return the trustDistributionPointURL
     *
     * @deprecated trustDistributionPointURL parameter is deprecated due to the introduction of new parameters(ipv4TDPSUrl,ipv6TDPSUrl) for the IPv4
     *             and IPv6 urls.
     */
    @Deprecated
    public String getTrustDistributionPointURL() {
        return trustDistributionPointURL;
    }

    /**
     * @param trustDistributionPointURL
     *            the trustDistributionPointURL to set
     * @deprecated trustDistributionPointURL parameter is deprecated due to the introduction of new parameters(ipv4TDPSUrl,ipv6TDPSUrl) for the IPv4
     *             and IPv6 urls.
     */
    @Deprecated
    public void setTrustDistributionPointURL(final String trustDistributionPointURL) {
        this.trustDistributionPointURL = trustDistributionPointURL;
    }

    /**
     * @return the ipv4TrustDistributionPointURL
     */
    public String getIpv4TrustDistributionPointURL() {
        return ipv4TrustDistributionPointURL;
    }

    /**
     * @param ipv4TrustDistributionPointURL
     *            the ipv4TrustDistributionPointURL to set
     */
    public void setIpv4TrustDistributionPointURL(final String ipv4TrustDistributionPointURL) {
        this.ipv4TrustDistributionPointURL = ipv4TrustDistributionPointURL;
    }

    /**
     * @return the ipv6TrustDistributionPointURL
     */
    public String getIpv6TrustDistributionPointURL() {
        return ipv6TrustDistributionPointURL;
    }

    /**
     * @param ipv6TrustDistributionPointURL
     *            the ipv6TrustDistributionPointURL to set
     */
    public void setIpv6TrustDistributionPointURL(final String ipv6TrustDistributionPointURL) {
        this.ipv6TrustDistributionPointURL = ipv6TrustDistributionPointURL;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((entityName == null) ? 0 : entityName.hashCode());
        result = prime * result + ((certificateSerialNumber == null) ? 0 : certificateSerialNumber.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
        result = prime * result + ((issuerDN == null) ? 0 : issuerDN.hashCode());
        result = prime * result + ((issuerFullDN == null) ? 0 : issuerFullDN.hashCode());
        result = prime * result + ((trustDistributionPointURL == null) ? 0 : trustDistributionPointURL.hashCode());
        result = prime * result + ((entityType == null) ? 0 : entityType.hashCode());
        result = prime * result + ((certificateStatus == null) ? 0 : certificateStatus.hashCode());
        result = prime * result + ((ipv4TrustDistributionPointURL == null) ? 0 : ipv4TrustDistributionPointURL.hashCode());
        result = prime * result + ((ipv6TrustDistributionPointURL == null) ? 0 : ipv6TrustDistributionPointURL.hashCode());
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
        final TrustedEntityInfo other = (TrustedEntityInfo) obj;
        if (entityName == null) {
            if (other.entityName != null) {
                return false;
            }
        } else if (!entityName.equals(other.entityName)) {
            return false;
        }

        if (certificateSerialNumber == null) {
            if (other.certificateSerialNumber != null) {
                return false;
            }
        } else if (!certificateSerialNumber.equals(other.certificateSerialNumber)) {
            return false;
        }

        if (subjectDN == null) {
            if (other.subjectDN != null) {
                return false;
            }
        } else if (!subjectDN.equals(other.subjectDN)) {
            return false;
        }

        if (issuerDN == null) {
            if (other.issuerDN != null) {
                return false;
            }
        } else if (!issuerDN.equals(other.issuerDN)) {
            return false;
        }

        if (issuerFullDN == null) {
            if (other.issuerFullDN != null) {
                return false;
            }
        } else if (!issuerFullDN.equals(other.issuerFullDN)) {
            return false;
        }

        if (trustDistributionPointURL == null) {
            if (other.trustDistributionPointURL != null) {
                return false;
            }
        } else if (!trustDistributionPointURL.equals(other.trustDistributionPointURL)) {
            return false;
        }

        if (entityType == null) {
            if (other.entityType != null) {
                return false;
            }
        } else if (!entityType.equals(other.entityType)) {
            return false;
        }

        if (certificateStatus == null) {
            if (other.certificateStatus != null) {
                return false;
            }
        } else if (!certificateStatus.equals(other.certificateStatus)) {
            return false;
        }

        if (ipv4TrustDistributionPointURL == null) {
            if (other.ipv4TrustDistributionPointURL != null) {
                return false;
            }
        } else if (!ipv4TrustDistributionPointURL.equals(other.ipv4TrustDistributionPointURL)) {
            return false;
        }

        if (ipv6TrustDistributionPointURL == null) {
            if (other.ipv6TrustDistributionPointURL != null) {
                return false;
            }
        } else if (!ipv6TrustDistributionPointURL.equals(other.ipv6TrustDistributionPointURL)) {
            return false;
        }

        return true;
    }

    @Override
    public String toString() {
        return "TrustDistributionPointInfo [entityName=" + entityName + ", entityType=" + entityType.getValue() + ", certificateSerialNumber="
                + certificateSerialNumber + ", subjectDN=" + subjectDN + ", issuerDN=" + issuerDN + ", issuerFullDN=" + issuerFullDN
                + ", certificateStatus=" + certificateStatus.value() + ", trustDistributionPointURL=" + trustDistributionPointURL
                + ", ipv4TrustDistributionPointURL=" + ipv4TrustDistributionPointURL + ", ipv6TrustDistributionPointURL="
                + ipv6TrustDistributionPointURL + "]";
    }

}
