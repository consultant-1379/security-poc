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
package com.ericsson.oss.itpf.security.kaps.model.holder;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;

/**
 * Holder class for X509v3CertificateBuilder which contains the serialNumber, notBefore, notAfter, subjectDN, issuerDN, subjectPublicKey, subjectUniqueIdentifier, subjectUniqueIdentifierValue, issuerUniqueIdentifier, extensionHolders
 *
 * @author xramcho
 *
 */
public class X509v3CertificateBuilderHolder implements Serializable {

    private static final long serialVersionUID = -6946559631546022342L;

    private BigInteger serialNumber;

    private Date notBefore;

    private Date notAfter;

    private String subjectDN;

    private String issuerDN;

    private PublicKey subjectPublicKey;

    protected boolean subjectUniqueIdentifier;

    protected String subjectUniqueIdentifierValue;

    protected boolean issuerUniqueIdentifier;

    private List<CertificateExtensionHolder> certificateExtensionHolders;

    /**
     * @return the subjectUniqueIdentifierValue
     */
    public String getSubjectUniqueIdentifierValue() {
        return subjectUniqueIdentifierValue;
    }

    /**
     * @param subjectUniqueIdentifierValue
     *            the subjectUniqueIdentifierValue to set
     */
    public void setSubjectUniqueIdentifierValue(final String subjectUniqueIdentifierValue) {
        this.subjectUniqueIdentifierValue = subjectUniqueIdentifierValue;
    }

    /**
     * @return the serialNumber
     */
    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    /**
     * @param serialNumber
     *            the serialNumber to set
     */
    public void setSerialNumber(final BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * @return the notBefore
     */
    public Date getNotBefore() {
        return notBefore;
    }

    /**
     * @param notBefore
     *            the notBefore to set
     */
    public void setNotBefore(final Date notBefore) {
        this.notBefore = notBefore;
    }

    /**
     * @return the notAfter
     */
    public Date getNotAfter() {
        return notAfter;
    }

    /**
     * @param notAfter
     *            the notAfter to set
     */
    public void setNotAfter(final Date notAfter) {
        this.notAfter = notAfter;
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
     * @return the issuerDN
     */
    public String getIssuerDN() {
        return issuerDN;
    }

    /**
     * @param issuerDN
     *            the issuerDN to set
     */
    public void setIssuerDN(final String issuerDN) {
        this.issuerDN = issuerDN;
    }

    /**
     * @return the subjectPublicKey
     */
    public PublicKey getSubjectPublicKey() {
        return subjectPublicKey;
    }

    /**
     * @param subjectPublicKey
     *            the subjectPublicKey to set
     */
    public void setSubjectPublicKey(final PublicKey subjectPublicKey) {
        this.subjectPublicKey = subjectPublicKey;
    }

    /**
     * @return the subjectUniqueIdentifier
     */
    public boolean isSubjectUniqueIdentifier() {
        return subjectUniqueIdentifier;
    }

    /**
     * @param subjectUniqueIdentifier
     *            the subjectUniqueIdentifier to set
     */
    public void setSubjectUniqueIdentifier(final boolean subjectUniqueIdentifier) {
        this.subjectUniqueIdentifier = subjectUniqueIdentifier;
    }

    /**
     * @return the issuerUniqueIdentifier
     */
    public boolean isIssuerUniqueIdentifier() {
        return issuerUniqueIdentifier;
    }

    /**
     * @param issuerUniqueIdentifier
     *            the issuerUniqueIdentifier to set
     */
    public void setIssuerUniqueIdentifier(final boolean issuerUniqueIdentifier) {
        this.issuerUniqueIdentifier = issuerUniqueIdentifier;
    }

    /**
     * @return the certificateExtensionHolders
     */
    public List<CertificateExtensionHolder> getCertificateExtensionHolders() {
        return certificateExtensionHolders;
    }

    /**
     * @param certificateExtensionHolders
     *            the certificateExtensionHolders to set
     */
    public void setCertificateExtensionHolders(final List<CertificateExtensionHolder> certificateExtensionHolders) {
        this.certificateExtensionHolders = certificateExtensionHolders;
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
        result = prime * result + (serialNumber == null ? 0 : serialNumber.hashCode());
        result = prime * result + (notBefore == null ? 0 : notBefore.hashCode());
        result = prime * result + (notAfter == null ? 0 : notAfter.hashCode());
        result = prime * result + (subjectDN == null ? 0 : subjectDN.hashCode());
        result = prime * result + (issuerDN == null ? 0 : issuerDN.hashCode());
        result = prime * result + (subjectPublicKey == null ? 0 : subjectPublicKey.hashCode());
        result = prime * result + (subjectUniqueIdentifier ? 1231 : 1237);
        result = prime * result + (issuerUniqueIdentifier ? 1231 : 1237);
        result = prime * result + (certificateExtensionHolders == null ? 0 : certificateExtensionHolders.hashCode());
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
        final X509v3CertificateBuilderHolder other = (X509v3CertificateBuilderHolder) obj;
        if (serialNumber == null) {
            if (other.serialNumber != null) {
                return false;
            }
        } else if (!serialNumber.equals(other.serialNumber)) {
            return false;
        }
        if (notBefore == null) {
            if (other.notBefore != null) {
                return false;
            }
        } else if (!notBefore.equals(other.notBefore)) {
            return false;
        }
        if (notAfter == null) {
            if (other.notAfter != null) {
                return false;
            }
        } else if (!notAfter.equals(other.notAfter)) {
            return false;
        }
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
        if (subjectUniqueIdentifier != other.subjectUniqueIdentifier) {
            return false;
        }
        if (issuerUniqueIdentifier != other.issuerUniqueIdentifier) {
            return false;
        }
        if (certificateExtensionHolders == null) {
            if (other.certificateExtensionHolders != null) {
                return false;
            }
        } else if (other.certificateExtensionHolders == null) {
            return false;
        } else {
            if (certificateExtensionHolders.size() != other.certificateExtensionHolders.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final CertificateExtensionHolder extensionHolder : certificateExtensionHolders) {
                for (final CertificateExtensionHolder extensionHolderOther : other.certificateExtensionHolders) {
                    if (extensionHolder.equals(extensionHolderOther)) {
                        isMatched = true;
                        break;
                    }
                }
                if (!isMatched) {
                    return false;
                }
                isMatched = false;
            }
        }
        return true;
    }

    @Override
    public String toString() {
        return "X509v3CertificateBuilderHolder [serialNumber=" + serialNumber + ", notBefore=" + notBefore + ", notAfter=" + notAfter + ", subjectDN=" + subjectDN + ", issuerDN=" + issuerDN
                + ", subjectPublicKey=" + subjectPublicKey + ", subjectUniqueIdentifier=" + subjectUniqueIdentifier + ", issuerUniqueIdentifier=" + issuerUniqueIdentifier
                + ", certificateExtensionHolders=" + certificateExtensionHolders + "]";
    }

}
