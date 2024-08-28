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
package com.ericsson.oss.itpf.security.pki.common.model.util;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;

/**
 * This class contains Utility methods for {@link CertificateAuthority} model class. It contains 1)getCACertificatesByStatus method for getting Certificate details of a CA based on CertificateStatus.
 * 
 * @author xramdag
 * 
 */
public class CertificateAuthorityUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateAuthorityUtil.class);

    private CertificateAuthorityUtil() {

    }

    /**
     * getCACertificatesByStatus is used to get the certificate details of CA with the given Certificate Status.
     * 
     * @param ca
     *            CertificateAuthority object from which the certificates are fetched.
     * @return List<Certificate> list of certificate objects of the CertificateAuthority with the given Certificate Status.
     * 
     */

    public static List<Certificate> getCACertificatesByStatus(final CertificateAuthority ca, final CertificateStatus certificateStatus) {
        LOGGER.debug("Getting Certificates for CA  {}  with the certificate status {}", ca.getName(), certificateStatus );
        final List<Certificate> certList = new ArrayList<Certificate>();

        switch (certificateStatus) {
        case ACTIVE:
            if (ca.getActiveCertificate() != null) {
                certList.add(ca.getActiveCertificate());
            }
            break;
        case INACTIVE:
            if (ca.getInActiveCertificates() != null) {
                for (Certificate cert : ca.getInActiveCertificates()) {
                    if (cert.getStatus().equals(CertificateStatus.INACTIVE)) {
                        certList.add(cert);
                    }
                }
            }
            break;
        case EXPIRED:
            if (ca.getInActiveCertificates() != null) {
                for (Certificate cert : ca.getInActiveCertificates()) {
                    if (cert.getStatus().equals(CertificateStatus.EXPIRED)) {
                        certList.add(cert);
                    }
                }
            }
            break;
        case REVOKED:
            if (ca.getInActiveCertificates() != null) {
                for (Certificate cert : ca.getInActiveCertificates()) {
                    if (cert.getStatus().equals(CertificateStatus.REVOKED)) {
                        certList.add(cert);
                    }
                }
            }
            break;
        }

        return certList;

    }

}
