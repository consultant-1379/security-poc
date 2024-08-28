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
import java.util.Date;
import java.util.List;

/**
 * Holder class for X509v2CRLBuilder which contains the subjectDN, thisUpdate, nextUpdate, revokedCertificateInfoHolders, extensionHolders
 *
 * @author xramcho
 *
 */
public class X509v2CRLBuilderHolder implements Serializable {

    private static final long serialVersionUID = -5722828622983889848L;

    private String subjectDN;

    private Date thisUpdate;

    private Date nextUpdate;

    private List<RevokedCertificateInfoHolder> revokedCertificateInfoHolders;

    private List<CertificateExtensionHolder> extensionHolders;

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
     * @return the thisUpdate
     */
    public Date getThisUpdate() {
        return thisUpdate;
    }

    /**
     * @param thisUpdate
     *            the thisUpdate to set
     */
    public void setThisUpdate(final Date thisUpdate) {
        this.thisUpdate = thisUpdate;
    }

    /**
     * @return the nextUpdate
     */
    public Date getNextUpdate() {
        return nextUpdate;
    }

    /**
     * @param nextUpdate
     *            the nextUpdate to set
     */
    public void setNextUpdate(final Date nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    /**
     * @return the revokedCertificateInfoHolders
     */
    public List<RevokedCertificateInfoHolder> getRevokedCertificateInfoHolders() {
        return revokedCertificateInfoHolders;
    }

    /**
     * @param revokedCertificateInfoHolders
     *            the revokedCertificateInfoHolders to set
     */
    public void setRevokedCertificateInfoHolders(final List<RevokedCertificateInfoHolder> revokedCertificateInfoHolders) {
        this.revokedCertificateInfoHolders = revokedCertificateInfoHolders;
    }

    /**
     * @return the extensionHolders
     */
    public List<CertificateExtensionHolder> getExtensionHolders() {
        return extensionHolders;
    }

    /**
     * @param extensionHolders
     *            the extensionHolders to set
     */
    public void setExtensionHolders(final List<CertificateExtensionHolder> extensionHolders) {
        this.extensionHolders = extensionHolders;
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
        result = prime * result + (subjectDN == null ? 0 : subjectDN.hashCode());
        result = prime * result + (thisUpdate == null ? 0 : thisUpdate.hashCode());
        result = prime * result + (nextUpdate == null ? 0 : nextUpdate.hashCode());
        result = prime * result + (revokedCertificateInfoHolders == null ? 0 : revokedCertificateInfoHolders.hashCode());
        result = prime * result + (extensionHolders == null ? 0 : extensionHolders.hashCode());
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
        final X509v2CRLBuilderHolder other = (X509v2CRLBuilderHolder) obj;
        if (subjectDN == null) {
            if (other.subjectDN != null) {
                return false;
            }
        } else if (!subjectDN.equals(other.subjectDN)) {
            return false;
        }
        if (thisUpdate == null) {
            if (other.thisUpdate != null) {
                return false;
            }
        } else if (!thisUpdate.equals(other.thisUpdate)) {
            return false;
        }
        if (nextUpdate == null) {
            if (other.nextUpdate != null) {
                return false;
            }
        } else if (!nextUpdate.equals(other.nextUpdate)) {
            return false;
        }
        if (revokedCertificateInfoHolders == null) {
            if (other.revokedCertificateInfoHolders != null) {
                return false;
            }
        } else if (other.revokedCertificateInfoHolders == null) {
            return false;
        } else {
            if (revokedCertificateInfoHolders.size() != other.revokedCertificateInfoHolders.size()) {
            return false;
            }
            boolean isMatched = false;
            for (final RevokedCertificateInfoHolder revokedCertificatesInfoHolder : revokedCertificateInfoHolders) {
                for (final RevokedCertificateInfoHolder revokedCertificatesInfoHolderOther : other.revokedCertificateInfoHolders) {
                    if (revokedCertificatesInfoHolder.equals(revokedCertificatesInfoHolderOther)) {
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
        if (extensionHolders == null) {
            if (other.extensionHolders != null) {
            return false;
            }
        } else if (other.extensionHolders == null) {
            return false;
        } else {
            if (extensionHolders.size() != other.extensionHolders.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final CertificateExtensionHolder extensionHolder : extensionHolders) {
                for (final CertificateExtensionHolder extensionHolderOther : other.extensionHolders) {
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
        return "X509v2CRLBuilderHolder [subjectDN=" + subjectDN + ", thisUpdate=" + thisUpdate + ", nextUpdate=" + nextUpdate + ", revokedCertificateInfoHolders=" + revokedCertificateInfoHolders
                + ", extensionHolders=" + extensionHolders + "]";
    }

}
