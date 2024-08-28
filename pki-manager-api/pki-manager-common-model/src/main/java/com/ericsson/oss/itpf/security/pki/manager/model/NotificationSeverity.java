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

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>
 * This is the enum of NotificationSeverity.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema for this class.
 * <p>
 * 
 * <pre>
 * &lt;simpleType name="NotificationSeverity">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="CRITICAL"/>
 *     &lt;enumeration value="MAJOR"/>
 *     &lt;enumeration value="WARNING"/>
 *     &lt;enumeration value="MINOR"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "NotificationSeverity")
@XmlEnum
public enum NotificationSeverity {

    @XmlEnumValue("CRITICAL")
    CRITICAL("critical", 1), @XmlEnumValue("MAJOR")
    MAJOR("major", 2), @XmlEnumValue("WARNING")
    WARNING("warning", 3), @XmlEnumValue("MINOR")
    MINOR("minor", 4);

    private int id;
    private String notificationSeverity;

    /**
     * Constructs NotificationSeverity object with severity status.
     * 
     * @param notificationSeverity
     *            notificationSeverity to be set.
     */
    private NotificationSeverity(final String notificationSeverity, final int id) {
        this.notificationSeverity = notificationSeverity;
        this.id = id;
    }

    public int getId() {
        return this.id;
    }

    public String value() {
        return notificationSeverity;
    }

    public static NotificationSeverity fromValue(final String v) {
        return valueOf(v);
    }

    public static NotificationSeverity getNotificationSeverity(final Integer id) {

        if (id == null) {
            return null;
        }

        for (final NotificationSeverity notificationSeverity : NotificationSeverity.values()) {
            if (id.equals(notificationSeverity.getId())) {
                return notificationSeverity;
            }
        }

        throw new IllegalArgumentException("No matching type for id " + id);
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Enum#toString()
     */
    @Override
    public String toString() {
        return super.toString();
    }

}
