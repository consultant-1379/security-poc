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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.result.mapper;

import java.io.Serializable;

/**
 * Class which has all the parameters required to notify if CA/Entity certificate gets expired.
 * 
 */

public class CertificateExpiryNotificationDetails implements Serializable {

    private static final long serialVersionUID = 6967963733323155554L;

    private String name;

    private String subjectDN;

    private String serialNumber;

    private Integer numberOfDays;

    private Integer periodBeforeExpiry;

    private Integer notificationSeverity;

    private Integer frequencyOfNotification;

    private String notificationMessage;

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name
     *            the name to set
     */
    public void setName(final String name) {
        this.name = name;
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
     * @return the serialNumber
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * @param serialNumber
     *            the serialNumber to set
     */
    public void setSerialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * @return the numberOfDays
     */
    public Integer getNumberOfDays() {
        return numberOfDays;
    }

    /**
     * @param numberOfDays
     *            the numberOfDays to set
     */
    public void setNumberOfDays(final Integer numberOfDays) {
        this.numberOfDays = numberOfDays;
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

    /*  *//**
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

    /**
     * Returns the hash code of object.
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        result = prime * result + ((numberOfDays == null) ? 0 : numberOfDays.hashCode());
        result = prime * result + ((periodBeforeExpiry == null) ? 0 : periodBeforeExpiry.hashCode());
        result = prime * result + ((notificationSeverity == null) ? 0 : notificationSeverity.hashCode());
        result = prime * result + ((frequencyOfNotification == null) ? 0 : frequencyOfNotification.hashCode());
        result = prime * result + ((notificationMessage == null) ? 0 : notificationMessage.hashCode());
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
        final CertificateExpiryNotificationDetails other = (CertificateExpiryNotificationDetails) obj;
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (subjectDN == null) {
            if (other.subjectDN != null) {
                return false;
            }
        } else if (!subjectDN.equals(other.subjectDN)) {
            return false;
        }
        if (serialNumber == null) {
            if (other.serialNumber != null) {
                return false;
            }
        } else if (!serialNumber.equals(other.serialNumber)) {
            return false;
        }
        if (numberOfDays == null) {
            if (other.numberOfDays != null) {
                return false;
            }
        } else if (!numberOfDays.equals(other.numberOfDays)) {
            return false;
        }

        if (periodBeforeExpiry == null) {
            if (other.periodBeforeExpiry != null) {
                return false;
            }
        } else if (!periodBeforeExpiry.equals(other.periodBeforeExpiry)) {
            return false;
        }

        if (notificationSeverity == null) {
            if (other.notificationSeverity != null) {
                return false;
            }
        } else if (!notificationSeverity.equals(other.notificationSeverity)) {
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

    /**
     * Returns string representation of {@link CertificateExpiryNotificationDetails} object.
     */
    @Override
    public String toString() {
        return "CertificateExpiryNotificationDetailsDTO [name=" + name + ", subjectDN=" + subjectDN + ", serialNumber=" + serialNumber + ", numberOfDays=" + numberOfDays + ", periodBeforeExpiry="
                + periodBeforeExpiry + ", notificationSeverity=" + notificationSeverity + ", frequencyOfNotification=" + frequencyOfNotification + ",notificationMessage=" + notificationMessage + "]";
    }

}
