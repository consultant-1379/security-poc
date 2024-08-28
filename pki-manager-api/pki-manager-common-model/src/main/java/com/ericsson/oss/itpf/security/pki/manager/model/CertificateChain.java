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

package com.ericsson.oss.itpf.security.pki.manager.model;

import java.io.Serializable;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;

/**
 * Contains complete chain of certificates from Entity to RootCA.
 */

public class CertificateChain implements Serializable {

    private static final long serialVersionUID = 6073436492438352279L;

    private List<Certificate> certificates;

    /**
     * @return the list of certificates
     */
    public List<Certificate> getCertificates() {
        return certificates;
    }

    /**
     * @param certificates
     *            list of certificates to set
     */
    public void setCertificateChain(final List<Certificate> certificateList) {
        certificates = certificateList;
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (certificates == null ? 0 : certificates.hashCode());
        return result;
    }

    /*
     * (non-Javadoc)
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
        final CertificateChain other = (CertificateChain) obj;
        if (certificates == null) {
            if (other.certificates != null) {
                return false;
            }
        } else if (other.certificates == null) {
            return false;
        } else {
            if (certificates.size() != other.certificates.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final Certificate certificate : certificates) {
                for (final Certificate certificateOther : other.certificates) {
                    if (certificate.equals(certificateOther)) {
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

}
