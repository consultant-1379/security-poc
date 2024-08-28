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
import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;

@Entity
@Table(name = "EntityProfile")
public class EntityProfileData extends AbstractProfileData implements Serializable {

    private static final long serialVersionUID = 7468248887140633069L;

    @Column(name = "subject_dn", columnDefinition = "TEXT", nullable = true)
    private String subjectDN;

    @Column(name = "subject_alt_name", columnDefinition = "TEXT", nullable = true)
    private String subjectAltName;

    @Column(name = "extended_key_usage_extension", columnDefinition = "TEXT", nullable = true)
    private String extendedKeyUsageExtension;

    @Column(name = "subject_unique_identifier_value", columnDefinition = "TEXT", nullable = true)
    private String subjectUniqueIdentifierValue;

    @Column(name = "key_usage_extension", columnDefinition = "TEXT", nullable = true)
    private String keyUsageExtension;

    @ManyToOne(fetch = FetchType.EAGER, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "entity_category_id", nullable = false)
    private EntityCategoryData entityCategoryData;

    @ManyToOne(fetch = FetchType.EAGER, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "key_generation_algorithm_id", nullable = true)
    private AlgorithmData keyGenerationAlgorithm;

    @ManyToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "certificate_profile_id", nullable = false)
    private CertificateProfileData certificateProfileData;

    @ManyToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinTable(name = "ENTITYPROFILE_TRUSTPROFILE", joinColumns = @JoinColumn(name = "entity_profile_id"), inverseJoinColumns = @JoinColumn(name = "trust_profile_id"))
    private Set<TrustProfileData> trustProfileDatas = new HashSet<TrustProfileData>();

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(final String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public String getExtendedKeyUsageExtension() {
        return extendedKeyUsageExtension;
    }

    public void setExtendedKeyUsageExtension(final String extendedKeyUsageExtension) {
        this.extendedKeyUsageExtension = extendedKeyUsageExtension;
    }

    public String getKeyUsageExtension() {
        return keyUsageExtension;
    }

    public void setKeyUsageExtension(final String keyUsageExtension) {
        this.keyUsageExtension = keyUsageExtension;
    }

    public AlgorithmData getKeyGenerationAlgorithm() {
        return keyGenerationAlgorithm;
    }

    public void setKeyGenerationAlgorithm(final AlgorithmData keyGenerationAlgorithm) {
        this.keyGenerationAlgorithm = keyGenerationAlgorithm;
    }

    public CertificateProfileData getCertificateProfileData() {
        return certificateProfileData;
    }

    public void setCertificateProfileData(final CertificateProfileData certificateProfileData) {
        this.certificateProfileData = certificateProfileData;
    }

    public Set<TrustProfileData> getTrustProfileDatas() {
        return trustProfileDatas;
    }

    public void setTrustProfileDatas(final Set<TrustProfileData> trustProfileDatas) {
        this.trustProfileDatas = trustProfileDatas;
    }

    /**
     * @return the subjectAltName
     */
    public String getSubjectAltName() {
        return subjectAltName;
    }

    /**
     * @param subjectAltName
     *            the subjectAltName to set
     */
    public void setSubjectAltName(final String subjectAltName) {
        this.subjectAltName = subjectAltName;
    }

    /**
     * @return the entityCategory
     */
    public EntityCategoryData getEntityCategory() {
        return entityCategoryData;
    }

    /**
     * @param entityCategory
     *            the entityCategory to set
     */
    public void setEntityCategory(final EntityCategoryData entityCategoryData) {
        this.entityCategoryData = entityCategoryData;
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
     * Returns a hash code value for the object
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((extendedKeyUsageExtension == null) ? 0 : extendedKeyUsageExtension.hashCode());
        result = prime * result + ((keyUsageExtension == null) ? 0 : keyUsageExtension.hashCode());
        result = prime * result + ((entityCategoryData == null) ? 0 : entityCategoryData.hashCode());
        result = prime * result + ((certificateProfileData == null) ? 0 : certificateProfileData.hashCode());
        result = prime * result + ((keyGenerationAlgorithm == null) ? 0 : keyGenerationAlgorithm.hashCode());
        result = prime * result + ((subjectAltName == null) ? 0 : subjectAltName.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
        result = prime * result + ((trustProfileDatas == null) ? 0 : trustProfileDatas.hashCode());
        result = prime * result + ((subjectUniqueIdentifierValue == null) ? 0 : subjectUniqueIdentifierValue.hashCode());
        return result;
    }

    /**
     * returns whether the invoking object is "equal to" the parameterized object
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

        final EntityProfileData other = (EntityProfileData) obj;

        if (extendedKeyUsageExtension == null) {
            if (other.extendedKeyUsageExtension != null) {
                return false;
            }
        } else if (!extendedKeyUsageExtension.equals(other.extendedKeyUsageExtension)) {
            return false;
        }
        if (keyUsageExtension == null) {
            if (other.keyUsageExtension != null) {
                return false;
            }
        } else if (!keyUsageExtension.equals(other.keyUsageExtension)) {
            return false;
        }
        if (certificateProfileData == null) {
            if (other.certificateProfileData != null) {
                return false;
            }
        } else if (!certificateProfileData.equals(other.certificateProfileData)) {
            return false;
        }

        if (keyGenerationAlgorithm == null) {
            if (other.keyGenerationAlgorithm != null) {
                return false;
            }
        } else if (!keyGenerationAlgorithm.equals(other.keyGenerationAlgorithm)) {
            return false;
        }
        if (subjectAltName == null) {
            if (other.subjectAltName != null) {
                return false;
            }
        } else if (!subjectAltName.equals(other.subjectAltName)) {
            return false;
        }
        if (subjectDN == null) {
            if (other.subjectDN != null) {
                return false;
            }
        } else if (!subjectDN.equals(other.subjectDN)) {
            return false;
        }
        if (entityCategoryData == null) {
            if (other.entityCategoryData != null) {
                return false;
            }
        } else if (!entityCategoryData.equals(other.entityCategoryData)) {
            return false;
        }
        if (trustProfileDatas == null && other.trustProfileDatas != null) {
            return false;
        } else if (trustProfileDatas != null && other.trustProfileDatas == null) {
            return false;
        } else if (trustProfileDatas != null && trustProfileDatas.size() != other.trustProfileDatas.size()) {
            return false;
        } else if (trustProfileDatas != null && other.trustProfileDatas != null) {
            boolean isMatched = false;
            for (final TrustProfileData trustProfileData : trustProfileDatas) {
                for (final TrustProfileData trustProfileDataOther : other.trustProfileDatas) {
                    if (trustProfileData.equals(trustProfileDataOther)) {
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
        if (subjectUniqueIdentifierValue == null) {
            if (other.subjectUniqueIdentifierValue != null) {
                return false;
            }
        } else if (!subjectUniqueIdentifierValue.equals(other.subjectUniqueIdentifierValue)) {
            return false;
        }
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "EntityProfileData [subjectDN=" + subjectDN + ", subjectAltName=" + subjectAltName + ", extendedKeyUsageExtension=" + extendedKeyUsageExtension + ", keyUsageExtension="
                + keyUsageExtension + ", entityCategoryData=" + entityCategoryData + ", keyGenerationAlgorithm=" + keyGenerationAlgorithm + ", certificateProfileData=" + certificateProfileData
                + ", trustProfileDatas=" + trustProfileDatas + ", subjectUniqueIdentifierValue=" + subjectUniqueIdentifierValue + "]";
    }

}
