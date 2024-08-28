package com.ericsson.oss.itpf.security.pki.manager.model.certificate;

import java.io.Serializable;

/**
 * This class containing Certificate fields which are used to identify the Certificate to be revoked.
 * 
 * <ul>
 * <li>subjectDN : subjectDN of Certificate.</li>
 * <li>issuerDN : issuerDN of Certificate.</li>
 * <li>cerficateSerialNumber : Serial Number of the Certificate.</li>
 * </ul>
 * 
 */
public class DNBasedCertificateIdentifier implements Serializable {

    private static final long serialVersionUID = -1570056555049830672L;

    private String issuerDN;

    private String subjectDN;

    private String cerficateSerialNumber;

    /**
     * 
     * @return the issuerDn
     */
    public String getIssuerDN() {
        return issuerDN;
    }

    /**
     * 
     * @param issuerDN
     *            the issuerDn to set
     */
    public void setIssuerDN(final String issuerDN) {
        this.issuerDN = issuerDN;
    }

    /**
     * @return the SubjectDn
     */
    public String getSubjectDN() {
        return subjectDN;
    }

    /**
     * 
     * @param subjectDN
     *            the subjectDN to set
     */
    public void setSubjectDN(final String subjectDN) {
        this.subjectDN = subjectDN;
    }

    /**
     * @return the cerficateSerialNumber
     */
    public String getCerficateSerialNumber() {
        return cerficateSerialNumber;
    }

    /**
     * 
     * @param cerficateSerialNumber
     *            the cerficateSerialNumber to set
     */
    public void setCerficateSerialNumber(final String cerficateSerialNumber) {
        this.cerficateSerialNumber = cerficateSerialNumber;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
        result = prime * result + ((issuerDN == null) ? 0 : issuerDN.hashCode());
        result = prime * result + ((cerficateSerialNumber == null) ? 0 : cerficateSerialNumber.hashCode());
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
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final DNBasedCertificateIdentifier other = (DNBasedCertificateIdentifier) obj;
        if (subjectDN == null) {
            if (other.subjectDN != null) {
                return false;
            }
        } else if (!subjectDN.equals(other.subjectDN)) {
            return false;
        }
        if (issuerDN == null) {
            if (other.issuerDN != null) {
                return false;
            }
        } else if (!issuerDN.equals(other.issuerDN)) {
            return false;
        }
        if (cerficateSerialNumber == null) {
            if (other.cerficateSerialNumber != null) {
                return false;
            }
        } else if (!cerficateSerialNumber.equals(other.cerficateSerialNumber)) {
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
        return "DNBasedCertificateIdentifier [subjectDN=" + subjectDN + ", issuerDN=" + issuerDN + ", cerficateSerialNumber=" + cerficateSerialNumber + "]";
    }

}
