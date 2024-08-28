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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import javax.persistence.*;

/**
 * This class is used to represent Certificate Expiry Notification Details JPA entity.
 * 
 * @author tcsviku
 * 
 */
@Entity
@Table(name = "certificate_expiry_notification_details")
public class CertificateExpiryNotificationDetailsData {

    @Id
    @SequenceGenerator(name = "SEQ_CERT_EXP_NOT_ID_GENERATOR", sequenceName = "SEQ_CERT_EXP_NOT_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_CERT_EXP_NOT_ID_GENERATOR")
    @Column(name = "id")
    private long id;

    @Column(name = "notification_severity", nullable = false)
    private Integer notificationSeverity;

    @Column(name = "period_before_expiry", nullable = false)
    private Integer periodBeforeExpiry;

    @Column(name = "frequency_of_notification", nullable = false)
    private Integer frequencyOfNotification;

    @Column(name = "notification_message", nullable = false)
    private String notificationMessage;

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
     * @return the notificationSeverity
     */
    public Integer getNotificationSeverity() {
        return notificationSeverity;
    }

    /**
     * @param notificationSeverity
     *            the notificationSeverity to set
     */
    public void setNotificationSeverity(final Integer notificationSeverity) {
        this.notificationSeverity = notificationSeverity;
    }

    /**
     * @return the periodBeforeExpiry
     */
    public Integer getPeriodBeforeExpiry() {
        return periodBeforeExpiry;
    }

    /**
     * @param periodBeforeExpiry
     *            the periodBeforeExpiry to set
     */
    public void setPeriodBeforeExpiry(final Integer periodBeforeExpiry) {
        this.periodBeforeExpiry = periodBeforeExpiry;
    }

    /**
     * @return the frequencyOfNotification
     */
    public Integer getFrequencyOfNotification() {
        return frequencyOfNotification;
    }

    /**
     * @param frequencyOfNotification
     *            the frequencyOfNotification to set
     */
    public void setFrequencyOfNotification(final Integer frequencyOfNotification) {
        this.frequencyOfNotification = frequencyOfNotification;
    }

    /**
     * @return the notificationMessage
     */
    public String getNotificationMessage() {
        return notificationMessage;
    }

    /**
     * @param notificationMessage
     *            the notificationMessage to set
     */
    public void setNotificationMessage(final String notificationMessage) {
        this.notificationMessage = notificationMessage;
    }

    @Override
    public String toString() {
        return "CertificateExpiryNotificationDetails [id=" + id + ", " + (null != notificationSeverity ? "notificationSeverity=" + notificationSeverity + ", " : "")
                + (null != periodBeforeExpiry ? "periodBeforeExpiry=" + periodBeforeExpiry + ", " : "")
                + (null != frequencyOfNotification ? "frequencyOfNotification=" + frequencyOfNotification + ", " : "")
                + (null != notificationMessage ? "notificationMessage=" + notificationMessage + ", " : "") + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((notificationSeverity == null) ? 0 : notificationSeverity.hashCode());
        result = prime * result + ((periodBeforeExpiry == null) ? 0 : periodBeforeExpiry.hashCode());
        result = prime * result + ((frequencyOfNotification == null) ? 0 : frequencyOfNotification.hashCode());
        result = prime * result + ((notificationMessage == null) ? 0 : notificationMessage.hashCode());
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
        if (!(obj instanceof CertificateExpiryNotificationDetailsData)) {
            return false;
        }
        final CertificateExpiryNotificationDetailsData other = (CertificateExpiryNotificationDetailsData) obj;

        if (id != other.id) {
            return false;
        }
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
        if (notificationMessage == null) {
            if (other.notificationMessage != null) {
                return false;
            }
        } else if (!notificationMessage.equals(other.notificationMessage)) {
            return false;
        }

        return true;
    }
}
