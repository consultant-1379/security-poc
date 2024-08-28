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
package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.Serializable;
import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

public class CredentialManagerCertificateIdentifier implements Serializable, Comparable<CredentialManagerCertificateIdentifier> {

    private static final long serialVersionUID = 7840863496683340682L;

    private X500Principal subjectDN;
    private X500Principal issuerDN;
    private BigInteger serialNumber;

    /**
     * Default constructor
     */
    public CredentialManagerCertificateIdentifier() {
        super();
    }

    /**
     * @param subjectDN
     * @param issuerDN
     * @param serialNumber
     */
    public CredentialManagerCertificateIdentifier(final X500Principal subjectDN, final X500Principal issuerDN, final BigInteger serialNumber) {
        super();
        this.subjectDN = subjectDN;
        this.issuerDN = issuerDN;
        this.serialNumber = serialNumber;
    }

    /**
     * @return the subjectDN
     */
    public X500Principal getSubjectDN() {
        return subjectDN;
    }

    /**
     * @return the issuerDN
     */
    public X500Principal getIssuerDN() {
        return issuerDN;
    }

    /**
     * @return the serialNumber
     */
    public BigInteger getSerialNumber() {
        return serialNumber;
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
        result = prime * result + ((issuerDN == null) ? 0 : issuerDN.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
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
        final CredentialManagerCertificateIdentifier other = (CredentialManagerCertificateIdentifier) obj;
        if (issuerDN == null) {
            if (other.issuerDN != null) {
                return false;
            }
        } else if (!issuerDN.equals(other.issuerDN)) {
            return false;
        }
        if (serialNumber == null) {
            if (other.serialNumber != null) {
                return false;
            }
        } else if (!serialNumber.equals(other.serialNumber)) {
            return false;
        }
        if (subjectDN == null) {
            if (other.subjectDN != null) {
                return false;
            }
        } else if (!subjectDN.equals(other.subjectDN)) {
            return false;
        }
        return true;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Comparable#compareTo(java.lang.Object)
     */
    @Override
    public int compareTo(final CredentialManagerCertificateIdentifier o) {
        if (subjectDN == null) {
            if (o.subjectDN != null) {
                return -1;
            }
        } else if (o.subjectDN == null) {
            return 1;
        } else {
            final int ret = subjectDN.getName().compareTo(o.subjectDN.getName());
            if (ret != 0) {
                return ret;
            }
        }
        if (issuerDN == null) {
            if (o.issuerDN != null) {
                return -1;
            }
        } else if (o.issuerDN == null) {
            return 1;
        } else {
            final int ret = issuerDN.getName().compareTo(o.issuerDN.getName());
            if (ret != 0) {
                return ret;
            }
        }
        if (serialNumber == null) {
            if (o.serialNumber != null) {
                return -1;
            } else {
                return 0;
            }
        } else if (o.serialNumber == null) {
            return 1;
        } else {
            return serialNumber.compareTo(o.serialNumber);
        }
    }
}
