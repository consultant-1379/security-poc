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
@Table(name = "entity")
public class EntityData extends AbstractEntityData {

    private static final long serialVersionUID = -544081299307635175L;

    @Id
    @SequenceGenerator(name = "SEQ_ENTITY_ID_GENERATOR", sequenceName = "SEQ_ENTITY_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_ENTITY_ID_GENERATOR")
    @Column(name = "id")
    private long id;

    @Embedded
    private EntityInfoData entityInfoData;

    @ManyToOne(fetch = FetchType.EAGER, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "key_generation_algorithm_id", nullable = true)
    private AlgorithmData keyGenerationAlgorithm;

    @ManyToOne(fetch = FetchType.EAGER, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "entity_category_id", nullable = false)
    private EntityCategoryData entityCategoryData;

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.PERSIST, CascadeType.MERGE }, orphanRemoval = true)
    @JoinTable(name = "entity_cert_exp_notification_details", joinColumns = @JoinColumn(name = "entity_id"), inverseJoinColumns = @JoinColumn(name = "entity_cert_exp_not_details_id"))
    private Set<CertificateExpiryNotificationDetailsData> certificateExpiryNotificationDetailsData = new HashSet<CertificateExpiryNotificationDetailsData>();

    @Column(name = "name_alias", nullable = true)
    private String nameAlias;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "otp_generated_time", nullable = true, updatable = true)
    private Date otpGeneratedTime;

    @Column(name = "otp_validity_period", nullable = true, updatable = true)
    private Integer otpValidityPeriod;

    /**
     * @return the nameAlias
     */
    public String getNameAlias() {
        return nameAlias;
    }

    /**
     * @param nameAlias
     *            the nameAlias to set
     */
    public void setNameAlias(final String nameAlias) {
        this.nameAlias = nameAlias;
    }

    /**
     * Sets current timestamp to createdDate and modifiedDate before persist of Entity in DB
     */
    @PrePersist
    protected void onCreate() {
        entityInfoData.setCreatedDate(new Date());
        entityInfoData.setModifiedDate(new Date());
        this.setOtpGeneratedTime(new Date());
    }

    /**
     * Sets current timestamp to modifiedDate before update of Entity in DB
     */
    @PreUpdate
    protected void onUpdate() {
        entityInfoData.setModifiedDate(new Date());
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
     * @return the entityInfoData
     */
    public EntityInfoData getEntityInfoData() {
        return entityInfoData;
    }

    /**
     * @param entityInfoData
     *            the entityInfoData to set
     */
    public void setEntityInfoData(final EntityInfoData entityInfoData) {
        this.entityInfoData = entityInfoData;
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
     * @return the entityCategoryData
     */
    public EntityCategoryData getEntityCategoryData() {
        return entityCategoryData;
    }

    /**
     * @param entityCategoryData
     *            the entityCategoryData to set
     */
    public void setEntityCategoryData(final EntityCategoryData entityCategoryData) {
        this.entityCategoryData = entityCategoryData;
    }

    /**
     * @return the certificateExpiryNotificationDetailsData
     */
    public Set<CertificateExpiryNotificationDetailsData> getCertificateExpiryNotificationDetailsData() {
        return certificateExpiryNotificationDetailsData;
    }

    /**
     * @param certificateExpiryNotificationDetailsData
     *            the certificateExpiryNotificationDetailsData to set
     */
    public void setCertificateExpiryNotificationDetailsData(final Set<CertificateExpiryNotificationDetailsData> certificateExpiryNotificationDetailsData) {
        this.certificateExpiryNotificationDetailsData = certificateExpiryNotificationDetailsData;
    }

    /**
     * @return the otpGeneratedDate
     */
    public Date getOtpGeneratedTime() {
        return otpGeneratedTime;
    }

    /**
     * @param otpGeneratedDate
     *            the otpGeneratedDate to set
     */
    public void setOtpGeneratedTime(final Date otpGeneratedTime) {
        this.otpGeneratedTime = otpGeneratedTime;
    }

    /**
     * @return the otpValidityPeriod
     */
    public Integer getOtpValidityPeriod() {
        return otpValidityPeriod;
    }

    /**
     * @param otpValidityPeriod
     *            the otpValidityPeriod to set
     */
    public void setOtpValidityPeriod(final Integer otpValidityPeriod) {
        this.otpValidityPeriod = otpValidityPeriod;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((certificateExpiryNotificationDetailsData == null) ? 0 : certificateExpiryNotificationDetailsData.hashCode());
        result = prime * result + ((entityCategoryData == null) ? 0 : entityCategoryData.hashCode());
        result = prime * result + ((entityInfoData == null) ? 0 : entityInfoData.hashCode());
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((keyGenerationAlgorithm == null) ? 0 : keyGenerationAlgorithm.hashCode());
        result = prime * result + ((nameAlias == null) ? 0 : nameAlias.hashCode());
        result = prime * result + ((otpGeneratedTime == null) ? 0 : otpGeneratedTime.hashCode());
        result = prime * result + ((otpValidityPeriod == null) ? 0 : otpValidityPeriod.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (getClass() != obj.getClass())
            return false;
        EntityData other = (EntityData) obj;
        if (certificateExpiryNotificationDetailsData == null) {
            if (other.certificateExpiryNotificationDetailsData != null)
                return false;
        } else if (!certificateExpiryNotificationDetailsData
                .equals(other.certificateExpiryNotificationDetailsData))
            return false;
        if (entityCategoryData == null) {
            if (other.entityCategoryData != null)
                return false;
        } else if (!entityCategoryData.equals(other.entityCategoryData))
            return false;
        if (entityInfoData == null) {
            if (other.entityInfoData != null)
                return false;
        } else if (!entityInfoData.equals(other.entityInfoData))
            return false;
        if (id != other.id)
            return false;
        if (keyGenerationAlgorithm == null) {
            if (other.keyGenerationAlgorithm != null)
                return false;
        } else if (!keyGenerationAlgorithm.equals(other.keyGenerationAlgorithm))
            return false;
        if (nameAlias == null) {
            if (other.nameAlias != null)
                return false;
        } else if (!nameAlias.equals(other.nameAlias))
            return false;
        if (otpGeneratedTime == null) {
            if (other.otpGeneratedTime != null)
                return false;
        } else if (!otpGeneratedTime.equals(other.otpGeneratedTime))
            return false;
        if (otpValidityPeriod == null) {
            if (other.otpValidityPeriod != null)
                return false;
        } else if (!otpValidityPeriod.equals(other.otpValidityPeriod))
            return false;
        return true;
    }

}