/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
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

import javax.xml.bind.annotation.*;
import javax.xml.datatype.Duration;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

/**
 * <p>
 * This class holds the information of CertificateExpiryNotificationDetails object values
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema for this class.
 * 
 * <pre>
 * &lt;complexType name="CertificateExpiryNotificationDetails">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="notificationSeverity" type="NotificationSeverity" minOccurs="0"/>
 *         &lt;element name="periodBeforeExpiry" type="xs:duration" minOccurs="0"/>
 *         &lt;element name="frequencyOfNotification" type="xs:duration" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CertificateExpiryNotificationDetails", propOrder = { "notificationSeverity", "periodBeforeExpiry", "frequencyOfNotification" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class CertificateExpiryNotificationDetails implements Serializable {

    private static final long serialVersionUID = 4768456919549865739L;

    @XmlElement(name = "NotificationSeverity", required = true)
    protected NotificationSeverity notificationSeverity;
    @XmlElement(name = "PeriodBeforeExpiry", required = true)
    protected Duration periodBeforeExpiry;
    @XmlElement(name = "FrequencyOfNotification", required = true)
    protected Duration frequencyOfNotification;

    /**
     * @return the notificationSeverity
     */
    public NotificationSeverity getNotificationSeverity() {
        return notificationSeverity;
    }

    /**
     * @param notificationSeverity
     *            the notificationSeverity to set
     */
    public void setNotificationSeverity(final NotificationSeverity notificationSeverity) {
        this.notificationSeverity = notificationSeverity;
    }

    /**
     * @return the periodBeforeExpiry
     */
    public Duration getPeriodBeforeExpiry() {
        return periodBeforeExpiry;
    }

    /**
     * @param periodBeforeExpiry
     *            the periodBeforeExpiry to set
     */
    public void setPeriodBeforeExpiry(final Duration periodBeforeExpiry) {
        this.periodBeforeExpiry = periodBeforeExpiry;
    }

    /**
     * @return the frequencyOfNotification
     */
    public Duration getFrequencyOfNotification() {
        return frequencyOfNotification;
    }

    /**
     * @param frequencyOfNotification
     *            the frequencyOfNotification to set
     */
    public void setFrequencyOfNotification(final Duration frequencyOfNotification) {
        this.frequencyOfNotification = frequencyOfNotification;
    }

    @Override
    public String toString() {
        return "CertificateExpiryNotificationDetails [" + (null != notificationSeverity ? "notificationSeverity=" + notificationSeverity + ", " : "")
                + (null != periodBeforeExpiry ? "periodBeforeExpiry=" + periodBeforeExpiry + ", " : "")
                + (null != frequencyOfNotification ? "frequencyOfNotification=" + frequencyOfNotification + ", " : "") + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((notificationSeverity == null) ? 0 : notificationSeverity.hashCode());
        result = prime * result + ((periodBeforeExpiry == null) ? 0 : periodBeforeExpiry.hashCode());
        result = prime * result + ((frequencyOfNotification == null) ? 0 : frequencyOfNotification.hashCode());
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
        if (!(obj instanceof CertificateExpiryNotificationDetails)) {
            return false;
        }
        final CertificateExpiryNotificationDetails other = (CertificateExpiryNotificationDetails) obj;

        if (notificationSeverity != other.notificationSeverity) {
            return false;
        }
        if (periodBeforeExpiry == null) {
            if (other.periodBeforeExpiry != null) {
                return false;
            }
        } else if (!periodBeforeExpiry.equals(other.periodBeforeExpiry)) {
            return false;
        }
        if (frequencyOfNotification == null) {
            if (other.frequencyOfNotification != null) {
                return false;
            }
        } else if (!frequencyOfNotification.equals(other.frequencyOfNotification)) {
            return false;
        }

        return true;
    }

}
