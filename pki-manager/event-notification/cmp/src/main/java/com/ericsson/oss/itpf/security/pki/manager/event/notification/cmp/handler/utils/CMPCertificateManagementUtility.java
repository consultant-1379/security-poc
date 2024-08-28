/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils;

import java.io.IOException;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.EJB;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.CertificateUtils;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CertificateManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

/**
 * This class is used to generate UserCertificate,TrustCertificates and ExtraCertificates required to build response message.
 * 
 * @author tcsramc
 *
 */
public class CMPCertificateManagementUtility {

    @EJB
    CertificateManagementLocalService certificateManagementLocalService;

    /**
     * This method is used to generate user certificate for the required entity based on certificate request.
     * 
     * @param entityName
     *            for which certificate has to be generated.
     * @param certificateRequest
     *            based on which certificate has to be generated.
     * @return x509certificate
     * @throws IOException
     *             is thrown if any I/O error occurs.
     */
    public X509Certificate getUserCertificate(final String entityName, final CertificateRequest certificateRequest) throws IOException {
        final Certificate userCertificate = certificateManagementLocalService.generateCertificate(entityName, certificateRequest);

        final X509Certificate x509UserCertificate = userCertificate.getX509Certificate();
        return x509UserCertificate;
    }

    /**
     * This method is used to get certificate chain(till rootCA excluding user certificate) for the given entity.
     * 
     * @param entityName
     *            for which certificate chain has to be fetched.
     * @return Certificate chain as a List of X509Certificates.
     */
    public List<X509Certificate> getCertificateChain(final String entityName) {
        final CertificateChain certificateChain = certificateManagementLocalService.getCertificateChain(entityName);
        final List<X509Certificate> x509ExtraCertificates = CertificateUtils.convert(certificateChain.getCertificates());
        x509ExtraCertificates.remove(0);
        return x509ExtraCertificates;
    }

    /**
     * This method is used to fetch trust Certificates for the given entity.
     * 
     * @param entityName
     *            for which trust certificates has to be fetched.
     * @return trust certificates as a list of X509Certificates.
     */
    public List<X509Certificate> getTrustCertificates(final String entityName) {
        final List<Certificate> trustCertificates = certificateManagementLocalService.getTrustCertificates(entityName);
        final List<X509Certificate> x509trustedCertificates = CertificateUtils.convert(trustCertificates);
        return x509trustedCertificates;
    }
}
