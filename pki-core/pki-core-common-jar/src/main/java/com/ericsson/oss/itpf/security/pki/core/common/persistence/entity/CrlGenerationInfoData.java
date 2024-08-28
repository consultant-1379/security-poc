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
package com.ericsson.oss.itpf.security.pki.core.common.persistence.entity;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;

@Entity
@Table(name = "crl_generation_info")
public class CrlGenerationInfoData implements Serializable {

    private static final long serialVersionUID = -4367830316302796423L;

    @Id
    @Column(name = "id")
    @SequenceGenerator(name = "SEQ_CRL_GENERATION_INFO_ID_GENERATOR", sequenceName = "SEQ_CRL_GENERATION_INFO_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_CRL_GENERATION_INFO_ID_GENERATOR")
    private long id;

    @Column(name = "validity_period", nullable = false)
    private String validityPeriod;

    @Column(name = "skew_crl_time", nullable = false)
    private String skewCrlTime;

    @Column(name = "overlap_period", nullable = false)
    private String overlapPeriod;

    @Column(name = "version", nullable = false)
    private int version;

    // JSON String
    @Column(name = "crl_extensions", columnDefinition = "TEXT")
    private String crlExtensionsJSONData;

    @OneToOne(fetch = FetchType.EAGER, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "signature_algorithm_id", nullable = true)
    private AlgorithmData signatureAlgorithm;

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.PERSIST })
    @JoinTable(name = "CRL_GENERATION_INFO_CA_CERTIFICATE", joinColumns = @JoinColumn(name = "crl_generation_info_id"), inverseJoinColumns = @JoinColumn(name = "certificate_id"))
    private Set<CertificateData> caCertificate = new HashSet<>();

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
     * @return the validityPeriod
     */
    public String getValidityPeriod() {
        return validityPeriod;
    }

    /**
     * @param validityPeriod
     *            the validityPeriod to set
     */
    public void setValidityPeriod(final String validityPeriod) {
        this.validityPeriod = validityPeriod;
    }

    /**
     * @return the skewCrlTime
     */
    public String getSkewCrlTime() {
        return skewCrlTime;
    }

    /**
     * @param skewCrlTime
     *            the skewCrlTime to set
     */
    public void setSkewCrlTime(final String skewCrlTime) {
        this.skewCrlTime = skewCrlTime;
    }

    /**
     * @return the overlapPeriod
     */
    public String getOverlapPeriod() {
        return overlapPeriod;
    }

    /**
     * @param overlapPeriod
     *            the overlapPeriod to set
     */
    public void setOverlapPeriod(final String overlapPeriod) {
        this.overlapPeriod = overlapPeriod;
    }

    /**
     * @return the version
     */
    public int getVersion() {
        return version;
    }

    /**
     * @param version
     *            the version to set
     */
    public void setVersion(final int version) {
        this.version = version;
    }

    /**
     * /**
     * 
     * @return the crlExtensions
     */
    public String getCrlExtensionsJSONData() {
        return crlExtensionsJSONData;
    }

    /**
     * @param crlExtensions
     *            the crlExtensions to set
     */
    public void setCrlExtensionsJSONData(final String crlExtensions) {
        this.crlExtensionsJSONData = crlExtensions;
    }

    /**
     * @return the signatureAlgorithm
     */
    public AlgorithmData getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * @param signatureAlgorithm
     *            the signatureAlgorithm to set
     */
    public void setSignatureAlgorithm(final AlgorithmData signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /**
     * @return the caCertificate
     */
    public Set<CertificateData> getCaCertificate() {
        return caCertificate;
    }

    /**
     * @param caCertificate
     *            the caCertificate to set
     */
    public void setCaCertificate(final Set<CertificateData> caCertificate) {
        this.caCertificate = caCertificate;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((caCertificate == null) ? 0 : caCertificate.hashCode());
        result = prime * result + ((crlExtensionsJSONData == null) ? 0 : crlExtensionsJSONData.hashCode());
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((overlapPeriod == null) ? 0 : overlapPeriod.hashCode());
        result = prime * result + ((signatureAlgorithm == null) ? 0 : signatureAlgorithm.hashCode());
        result = prime * result + ((skewCrlTime == null) ? 0 : skewCrlTime.hashCode());
        result = prime * result + ((validityPeriod == null) ? 0 : validityPeriod.hashCode());
        result = prime * result + version;
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
        
        final CrlGenerationInfoData other = (CrlGenerationInfoData) obj;
        if (caCertificate == null) {
            if (other.caCertificate != null) {
                return false;
            }
        } else if (!caCertificate.equals(other.caCertificate)) {
            return false;
        }
        
        if (crlExtensionsJSONData == null) {
            if (other.crlExtensionsJSONData != null) {
                return false;
            }
        } else if (!crlExtensionsJSONData.equals(other.crlExtensionsJSONData)) {
            return false;
        }
        
        if (id != other.id) {
            return false;
        }
        if (overlapPeriod == null) {
            if (other.overlapPeriod != null) {
                return false;
            }
        } else if (!overlapPeriod.equals(other.overlapPeriod)) {
            return false;
        }
        
        if (signatureAlgorithm != other.signatureAlgorithm) {
            return false;
        }
        if (skewCrlTime == null) {
            if (other.skewCrlTime != null) {
                return false;
            }
        } else if (!skewCrlTime.equals(other.skewCrlTime)) {
            return false;
        }
        
        if (validityPeriod == null) {
            if (other.validityPeriod != null) {
                return false;
            }
        } else if (!validityPeriod.equals(other.validityPeriod)) {
            return false;
        }
        
        if (version != other.version) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "CrlGenerationInfoData [id=" + id + ", validityPeriod=" + validityPeriod + ", skewCrlTime=" + skewCrlTime + ", overlapPeriod=" + overlapPeriod + ", version=" + version
                + ", crlExtensions=" + crlExtensionsJSONData + ", signatureAlgorithm=" + signatureAlgorithm + ", caCertificate=" + caCertificate + "]";
    }

}
