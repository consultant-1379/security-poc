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
package com.ericsson.oss.itpf.security.pki.common.util;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateFactoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateIsNullException;

/**
 * This class represents the successful result of the PKIX certification path builder algorithm
 * 
 * @author tcsramc
 * 
 */
public class PKIXCertificatePathBuilder {

    @Inject
    Logger logger;
    private final static String Collection = "Collection";

    /**
     * <p>
     * This build method will provide a PKIXCertPathBuildResult which represents the successful result of the PKIX certification path builder algorithm. All certification paths that are built and
     * returned using this algorithm are also validated according to the PKIX certification path validation algorithm. Instances of PKIXCertPathBuilderResult are returned by the build method of
     * CertPathBuilder objects implementing the PKIX algorithm.
     * </p>
     * All PKIXCertPathBuilderResult objects contain the certification path constructed by the build algorithm, the valid policy tree and subject public key resulting from the build algorithm, and a
     * TrustAnchor describing the certification authority (CA) that served as a trust anchor for the certification path.
     * 
     * 
     * Validation will fail due to:
     * <p>
     * If the builder is unable to construct a certification path that satisfies the specified parameters
     * </p>
     * <p>
     * If the specified parameters are inappropriate for this CertPathBuilder
     * </p>
     * Hence resulting into GeneralSecurityException
     * 
     * @param userCertAndChain
     * @param trustedCertificates
     * @return
     * @throws CertPathBuilderException
     *             is thrown if the builder is unable to construct a certification path that satisfies the specified parameters
     * @throws NoSuchAlgorithmException
     *             is thrown if unsupported algorithm encounters.
     * @throws GeneralSecurityException
     *             is thrown if any type safety violation occurs.
     */
    public PKIXCertPathBuilderResult build(final X509Certificate userCertificate, final Set<X509Certificate> intermediateCerts, final Set<X509Certificate> trustedCertificates)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, CertPathBuilderException, CertificateIsNullException {
            logger.info("Building the PKIXCertPathBuildResult based on CertPathBuilder objects implementing the PKIX algorithm");
        if (userCertificate == null) {
            logger.error("User-certificate set is NULL, hence Usercertificate cannot be fetched");
            throw new CertificateIsNullException(ErrorMessages.CERTIFICATE_IS_NULL);
        }
        final Set<TrustAnchor> trustAnchors = getTrustAnchors(trustedCertificates);
        final X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(userCertificate);
        final PKIXBuilderParameters pKIXParams = new PKIXBuilderParameters(trustAnchors, selector);
        final PKIXCertPathBuilderResult result = getPKIXCertPathBuilderResult(pKIXParams, intermediateCerts);

        return result;

    }

    /**
     * Returns certificateChain from PKIXCertPathBuilderResult.
     * 
     * @param result
     *            PKIXCertPathBuilderResult from which certificate chain needs to be extracted.
     * @return
     * @throws CertificateException
     *             is thrown when error occurs while generating certificate.
     * @throws CertificateIsNullException
     *             is thrown certificate can not be generated from given certificate factory
     * @throws CertificateFactoryNotFoundException
     *             is thrown in case CertificateFactory can not be instantiated properly for X509 Certificate type
     */
    public Set<X509Certificate> getCertificateChain(final PKIXCertPathBuilderResult result) throws CertificateException, CertificateIsNullException, CertificateFactoryNotFoundException,
            CertificateFactoryNotFoundException {
        logger.info("Extracting Certificate chain from PKIXCertPathBuilderResult.");
        final Set<X509Certificate> certChain = new HashSet<X509Certificate>();
        final CertificateFactory certificateFactory = CertificateFactory.getInstance(Constants.X509);
        if (certificateFactory == null) {
            logger.error("Error Occured while forming X509 instance to generate certificate");
            throw new CertificateFactoryNotFoundException(ErrorMessages.CERTIFICATE_FACTORY_NOT_FOUND);
        }
        for (final Certificate certificate : result.getCertPath().getCertificates()) {
            final X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
            if (x509Certificate == null) {
                logger.error("Error Occured while forming X509 instance to generate certificate");
                throw new CertificateIsNullException(ErrorMessages.CERTIFICATE_IS_NULL);
            }
            certChain.add(x509Certificate);
        }
        
        certChain.add(result.getTrustAnchor().getTrustedCert());
        return certChain;
    }

    private Set<TrustAnchor> getTrustAnchors(final Set<X509Certificate> trustedCertificates) {
        final Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
        for (final X509Certificate trustedRootCert : trustedCertificates) {
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));
        }
        return trustAnchors;
    }

    private PKIXCertPathBuilderResult getPKIXCertPathBuilderResult(final PKIXBuilderParameters pKIXParams, final Set<X509Certificate> intermediateCerts) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, CertPathBuilderException {

        pKIXParams.setRevocationEnabled(false);
        if (intermediateCerts != null) {
            final CertStore intermediateCertStore = CertStore.getInstance(Collection, new CollectionCertStoreParameters(intermediateCerts));
            pKIXParams.addCertStore(intermediateCertStore);
        }
        final CertPathBuilder builder = CertPathBuilder.getInstance(Constants.PKIX_BUILDER);
        final PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder.build(pKIXParams);
        return result;
    }

}
