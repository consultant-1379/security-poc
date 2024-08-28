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

import java.util.*;

import javax.persistence.*;

@Entity
@Table(name = "CAEntity")
public class CAEntityData extends AbstractEntityData {

    private static final long serialVersionUID = 1558631726100620772L;

    @Id
    @SequenceGenerator(name = "SEQ_CA_ID_GENERATOR", sequenceName = "SEQ_CA_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_CA_ID_GENERATOR")
    @Column(name = "id")
    private long id;

    @Embedded
    private CertificateAuthorityData certificateAuthorityData;

    @ManyToOne(fetch = FetchType.EAGER, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "key_generation_algorithm_id", nullable = true)
    private AlgorithmData keyGenerationAlgorithm;

    @OneToMany(mappedBy = "issuerData", fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    private Set<CertificateProfileData> certificateProfiles = new HashSet<CertificateProfileData>();

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.PERSIST, CascadeType.MERGE }, orphanRemoval = true)
    @JoinTable(name = "ca_cert_exp_notification_details", joinColumns = @JoinColumn(name = "ca_id"), inverseJoinColumns = @JoinColumn(name = "ca_cert_exp_not_details_id"))
    private Set<CertificateExpiryNotificationDetailsData> certificateExpiryNotificationDetailsData = new HashSet<CertificateExpiryNotificationDetailsData>();

    /**
     * Sets current timestamp to createdDate and modifiedDate before persist of Algorithm in DB
     */
    @PrePersist
    protected void onCreate() {
        certificateAuthorityData.setCreatedDate(new Date());
        certificateAuthorityData.setModifiedDate(new Date());
    }

    /**
     * Sets current timestamp to modifiedDate before update of Algorithm in DB
     */
    @PreUpdate
    protected void onUpdate() {
        certificateAuthorityData.setModifiedDate(new Date());
    }

    // BEGIN dDU-TORF-47941 - DESPICABLE_US
    @Column(name = "is_external_ca", nullable = false)
    private boolean externalCA;

    @ManyToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.PERSIST, CascadeType.MERGE })
    @JoinTable(name = "CAENTITYASSOCIATION", joinColumns = @JoinColumn(name = "caentity_id"), inverseJoinColumns = @JoinColumn(name = "associatedcaentity_id"))
    private Set<CAEntityData> associated = new HashSet<CAEntityData>();

    // END dDU-TORF-47941 - DESPICABLE_US

    // BEGIN dDU-TORF-47941 - DESPICABLE_US
    /**
     * @return the isExternalCA
     */
    public boolean isExternalCA() {
        return externalCA;
    }

    /**
     * @param isExternalCA
     *            the isExternalCA to set
     */
    public void setExternalCA(final boolean externalCA) {
        this.externalCA = externalCA;
    }

    // END dDU-TORF-47941 - DESPICABLE_US

    /**
     * @return the associated
     */
    public Set<CAEntityData> getAssociated() {
        return associated;
    }

    /**
     * @param associated
     *            the associated to set
     */
    public void setAssociated(final Set<CAEntityData> associated) {
        this.associated = associated;
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
     * @return the certificateAuthorityData
     */
    public CertificateAuthorityData getCertificateAuthorityData() {
        return certificateAuthorityData;
    }

    /**
     * @param certificateAuthorityData
     *            the certificateAuthorityData to set
     */
    public void setCertificateAuthorityData(final CertificateAuthorityData certificateAuthorityData) {
        this.certificateAuthorityData = certificateAuthorityData;
    }

    /**
     * @return the keyGenerationAlgorithm
     */
    public AlgorithmData getKeyGenerationAlgorithm() {
        return keyGenerationAlgorithm;
    }

    /**
     * @param keyGenerationAlgorithm
     *            the keyGenerationAlgorithm to set
     */
    public void setKeyGenerationAlgorithm(final AlgorithmData keyGenerationAlgorithm) {
        this.keyGenerationAlgorithm = keyGenerationAlgorithm;
    }

    /**
     * @return the certificateProfiles
     */
    public Set<CertificateProfileData> getCertificateProfiles() {
        return certificateProfiles;
    }

    /**
     * @param certificateProfiles
     *            the certificateProfiles to set
     */
    public void setCertificateProfiles(final Set<CertificateProfileData> certificateProfiles) {
        this.certificateProfiles = certificateProfiles;
    }

    /**
     * @return the certificateExpiryNotificationDetails
     */
    public Set<CertificateExpiryNotificationDetailsData> getCertificateExpiryNotificationDetailsData() {
        return certificateExpiryNotificationDetailsData;
    }

    /**
     * @param certificateExpiryNotificationDetails
     *            the certificateExpiryNotificationDetails to set
     */
    public void setCertificateExpiryNotificationDetailsData(final Set<CertificateExpiryNotificationDetailsData> certificateExpiryNotificationDetailsData) {
        this.certificateExpiryNotificationDetailsData = certificateExpiryNotificationDetailsData;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return super.toString() + "CAEntityData [id=" + id + ", " + (certificateAuthorityData != null ? "certificateAuthorityData=" + certificateAuthorityData + ", " : "")
                + (keyGenerationAlgorithm != null ? "keyGenerationAlgorithm=" + keyGenerationAlgorithm + ", " : "")
                + (certificateProfiles != null ? "certificateProfiles=" + certificateProfiles + ", " : "") + "externalCA=" + externalCA + ", " + (associated != null ? "associated=" + associated : "")
                + (null != certificateExpiryNotificationDetailsData ? "certificateExpiryNotificationDetails=" + certificateExpiryNotificationDetailsData : "") + "]";
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((associated == null) ? 0 : associated.hashCode());
        result = prime * result + ((certificateAuthorityData == null) ? 0 : certificateAuthorityData.hashCode());
        result = prime * result + ((certificateExpiryNotificationDetailsData == null) ? 0 : certificateExpiryNotificationDetailsData.hashCode());
        result = prime * result + ((certificateProfiles == null) ? 0 : certificateProfiles.hashCode());
        result = prime * result + (externalCA ? 1231 : 1237);
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((keyGenerationAlgorithm == null) ? 0 : keyGenerationAlgorithm.hashCode());
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
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CAEntityData other = (CAEntityData) obj;
        if (associated == null) {
            if (other.associated != null) {
                return false;
            }
        } else if (!associated.equals(other.associated)) {
            return false;
        }
        if (certificateAuthorityData == null) {
            if (other.certificateAuthorityData != null) {
                return false;
            }
        } else if (!certificateAuthorityData.equals(other.certificateAuthorityData)) {
            return false;
        }
        if (certificateProfiles == null && other.certificateProfiles != null) {
            return false;
        } else if (certificateProfiles != null && other.certificateProfiles == null) {

            return false;
        } else if (certificateProfiles != null && certificateProfiles.size() != other.certificateProfiles.size()) {
            return false;
        } else if (certificateProfiles != null && other.certificateProfiles != null) {
            boolean isMatched = false;
            for (final CertificateProfileData certificateProfile : certificateProfiles) {
                for (final CertificateProfileData certificateProfileOther : other.certificateProfiles) {
                    if (certificateProfile.equals(certificateProfileOther)) {
                        isMatched = true;
                        break;
                    }
                }
                if (!isMatched) {
                    return false;
                }
                isMatched = false;
            }
        }
        if (externalCA != other.externalCA) {
            return false;
        }
        if (id != other.id) {
            return false;
        }
        if (keyGenerationAlgorithm == null) {
            if (other.keyGenerationAlgorithm != null) {
                return false;
            }
        } else if (!keyGenerationAlgorithm.equals(other.keyGenerationAlgorithm)) {
            return false;
        }

        if (certificateExpiryNotificationDetailsData == null) {
            if (other.certificateExpiryNotificationDetailsData != null) {
                return false;
            }
        } else if (!certificateExpiryNotificationDetailsData.equals(other.certificateExpiryNotificationDetailsData)) {
            return false;
        }
        return true;
    }

}
