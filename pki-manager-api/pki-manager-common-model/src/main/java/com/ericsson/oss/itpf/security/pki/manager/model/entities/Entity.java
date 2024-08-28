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

package com.ericsson.oss.itpf.security.pki.manager.model.entities;

import java.io.Serializable;
import java.util.Date;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * <p>
 * This class extends Abstract Entity Class. Entity should be created before generating a certificate. It holds various properties of entity for creating certificate. A entity should be mapped to one
 * entity profile. Subject is optional for entity. If subject is not provided subject alt name should be provided and vice versa.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="Entity">
 *   &lt;complexContent>
 *     &lt;extension base="{}AbstractEntity">
 *       &lt;sequence>
 *       &lt;element name="EntityInfo" type="EntityInfo" minOccurs="1" />
 *       &lt;element name="KeyGenerationAlgorithm" type="Algorithm" minOccurs="0"  maxOccurs="unbounded" />
 *       &lt;element name="Category" type="EntityCategory" minOccurs="0" />
 *       &lt;element name="OTPValidityPeriod" type="integer" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement(name = "Entity")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Entity", propOrder = { "keyGenerationAlgorithm", "category", "entityInfo", "otpValidityPeriod" })
public class Entity extends AbstractEntity implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = 4053830746674212222L;

    @XmlElement(name = "KeyGenerationAlgorithm", required = false)
    protected Algorithm keyGenerationAlgorithm;
    @XmlElement(name = "Category", required = true)
    protected EntityCategory category;
    @XmlElement(name = "EntityInfo", required = true)
    protected EntityInfo entityInfo;

    /**
     * For create/update Entity, if operator don't pass otpValidityPeriod value, default configured value will be set.
     */
    @XmlElement(name = "OTPValidityPeriod", required = false)
    protected Integer otpValidityPeriod;

    /**
     * 
     */
    public Entity() {
        this.type = EntityType.ENTITY;
    }

    /**
     * @return the entityInfo
     */
    public EntityInfo getEntityInfo() {
        return entityInfo;
    }

    /**
     * @param entityInfo
     *            the entityInfo to set
     */
    public void setEntityInfo(final EntityInfo entityInfo) {
        this.entityInfo = entityInfo;
    }

    /**
     * @return the keyGenerationAlgorithms
     */
    public Algorithm getKeyGenerationAlgorithm() {
        return keyGenerationAlgorithm;
    }

    /**
     * @param certificateProfiles
     *            the certificateProfiles to set
     */
    public void setKeyGenerationAlgorithm(final Algorithm keyGenerationAlgorithm) {
        this.keyGenerationAlgorithm = keyGenerationAlgorithm;
    }

    /**
     * @return the category
     */
    public EntityCategory getCategory() {
        return category;
    }

    /**
     * @param category
     *            the category to set
     */
    public void setCategory(final EntityCategory category) {
        this.category = category;
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

    /**
     * Returns a string representation of the Entity object
     */
    @Override
    public String toString() {
        return "Entity [" + super.toString() + ", " + (null != entityInfo ? "entityInfo=" + entityInfo : "")
                + (null != keyGenerationAlgorithm ? "keyGenerationAlgorithm=" + keyGenerationAlgorithm : "") + (category != null ? "category=" + category : "")
                + (otpValidityPeriod != null ? "otpValidityPeriod=" + otpValidityPeriod + ", " : "") + "]";
    }

    /**
     * Returns a hash code value for the Entity object
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((entityInfo == null) ? 0 : entityInfo.hashCode());
        result = prime * result + ((keyGenerationAlgorithm == null) ? 0 : keyGenerationAlgorithm.hashCode());
        result = prime * result + ((category == null) ? 0 : category.hashCode());
        result = prime * result + ((otpValidityPeriod == null) ? 0 : otpValidityPeriod.hashCode());
        return result;
    }

    /**
     * Indicates whether some other object is "equal to" this one.
     * 
     * @param obj
     *            the reference object with which to compare.
     * @return true if this object is the same as the obj argument; false otherwise.
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
        final Entity other = (Entity) obj;
        if (entityInfo == null) {
            if (other.entityInfo != null) {
                return false;
            }
        } else if (!entityInfo.equals(other.entityInfo)) {
            return false;
        }
        if (keyGenerationAlgorithm == null) {
            if (other.keyGenerationAlgorithm != null) {
                return false;
            }
        } else if (!keyGenerationAlgorithm.equals(other.keyGenerationAlgorithm)) {
            return false;
        }
        if (category == null) {
            if (other.category != null) {
                return false;
            }
        } else if (!category.equals(other.category)) {
            return false;
        }
        if (otpValidityPeriod == null) {
            if (other.otpValidityPeriod != null) {
                return false;
            }
        } else if (!otpValidityPeriod.equals(other.otpValidityPeriod)) {
            return false;
        }
        return true;
    }
}
