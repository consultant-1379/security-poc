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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model;

import java.security.cert.X509Certificate;

/**
 * Model class which contains Root CA name and its certificate.
 */
public class CACertificateValidationInfo {

    private String caName;

    private X509Certificate certificate;

    private boolean isForceImport;

    /**
     * @return the caName
     */
    public String getCaName() {
        return caName;
    }

    /**
     * @param caName
     *            the caName to set
     */
    public void setCaName(final String caName) {
        this.caName = caName;
    }

    /**
     * @return the certificate
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * @param certificate
     *            the certificate to set
     */
    public void setCertificate(final X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * @return the isForceImport
     */
    public boolean isForceImport() {
        return isForceImport;
    }

    /**
     * @param isForceImport
     *            the isForceImport to set
     */
    public void setForceImport(final boolean isForceImport) {
        this.isForceImport = isForceImport;
    }

    /**
     * Returns hash code of the object.
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((caName == null) ? 0 : caName.hashCode());
        result = prime * result + ((certificate == null) ? 0 : certificate.hashCode());
        result = prime * result + (isForceImport ? 1231 : 1237);
        return result;
    }

    /**
     * Checks equality of two objects
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
        final CACertificateValidationInfo other = (CACertificateValidationInfo) obj;
        if (caName == null) {
            if (other.caName != null) {
                return false;
            }
        } else if (!caName.equals(other.caName)) {
            return false;
        }
        if (certificate == null) {
            if (other.certificate != null) {
                return false;
            }
        } else if (!certificate.equals(other.certificate)) {
            return false;
        }
        if (isForceImport != other.isForceImport) {
            return false;
        }
        return true;
    }

    /**
     * Returns string form of the object.
     */
    @Override
    public String toString() {
        return "CACertificateValidationInfo [caName=" + caName + ", certificate=" + certificate.getSubjectDN().toString() + ", isForceImport=" + isForceImport + "]";

    }

}
