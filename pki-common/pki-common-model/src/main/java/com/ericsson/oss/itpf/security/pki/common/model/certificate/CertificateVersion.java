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
package com.ericsson.oss.itpf.security.pki.common.model.certificate;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>
 * This enum contains supported versions of certificate.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 * <p>
 * 
 * <pre>
 * &lt;simpleType name="CertificateVersion">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="V3"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "CertificateVersion")
@XmlEnum
public enum CertificateVersion {
    V3(2);

    private int value;

    CertificateVersion(final int value) {
        this.value = value;
    }

    /**
     * Get Version Id value.
     * 
     * @return id value
     */
    public int value() {
        return value;
    }

    /**
     * Get Version Enum from value
     * 
     * @param value
     * @return Corresponding Version Enum
     */
    public static CertificateVersion fromValue(final int v) {
        for (final CertificateVersion c : CertificateVersion.values()) {
            if (c.value == v) {
                return c;
            }
        }
        throw new IllegalArgumentException(Integer.toString(v));
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
