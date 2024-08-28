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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.generator;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.inject.Inject;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.holder.CertificateExtensionHolder;
import com.ericsson.oss.itpf.security.kaps.model.holder.X509v3CertificateBuilderHolder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder.ExtensionBuilder;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.eserviceproxy.KeyAccessProviderServiceProxy;
import com.ericsson.oss.itpf.security.pki.core.common.utils.CertificateGenerationInfoParser;
import com.ericsson.oss.itpf.security.pki.core.common.utils.DateUtil;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException;

/**
 * This class generates {@link X5909Certificate} with all inputs passed.
 *
 */
public class CertificateGenerator {

    private static final Logger logger = LoggerFactory.getLogger(CertificateGenerator.class);

    @Inject
    DateUtil dateUtil;

    @Inject
    SerialNumberGenerator serialNumberGenerator;

    @Inject
    CertificateGenerationInfoParser certGenInfoParser;

    @Inject
    ExtensionBuilder extensionBuilder;

    @Inject
    KeyAccessProviderServiceProxy keyAccessProviderServiceProxy;

    @Inject
    SystemRecorder systemRecorder;


    static {
        try {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        } catch (SecurityException securityException) {
            logger.error("Cannot register BouncyCastleProvider", securityException);
        }
    }

    /**
     * Generates {@link X509Certificate} certificate from {@link CertificateGenerationInfo}.
     * 
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo} object which gives information to generate certificate.
     * @param keyIdentifier
     * @param publicKey
     *            publicKey of the CA.
     * @param extensions
     *            list of extensions that are to be included in the certificate.
     * @return certificate generated from the information passed.
     *
     * @throws CertificateGenerationException
     *             Throws in case any failure occurs in generating certificate.
     * @throws CertificateServiceException
     *             Throws in case any failure occurs in generating certificate.
     * @throws InvalidCertificateExtensionsException
     *             Thrown in case any failure occurs adding extensions to certificate.
     * @throws UnsupportedCertificateVersionException
     *             Thrown in case of certificate version is not supported.
     *
     */
    public X509Certificate generateCertificate(final CertificateGenerationInfo certificateGenerationInfo, final KeyIdentifier keyIdentifier, final PublicKey publicKey, final List<Extension> extensions)
            throws CertificateGenerationException, CertificateServiceException, InvalidCertificateExtensionsException, UnsupportedCertificateVersionException {

        logger.debug("Certificate signing with all the information started:{}", certificateGenerationInfo);
        CertificateAuthority certificateAuthority = null;
        X500Principal issuerDN = null;

        certificateAuthority = certificateGenerationInfo.getIssuerCA();

        if (certificateAuthority != null){
            issuerDN = certificateGenerationInfo.getIssuerCA().getActiveCertificate().getX509Certificate().getSubjectX500Principal();
        }

        logger.info("X500Principal issuertDN certificateGenerator:{}", issuerDN);
        final X509v3CertificateBuilderHolder x509v3CertificateBuilderHolder = buildX509v3CertificateBuilderHolder(certificateGenerationInfo, publicKey, extensions);

        try {
            final X509Certificate certificate = keyAccessProviderServiceProxy.getKeyAccessProviderService().signCertificate(keyIdentifier, certificateGenerationInfo.getIssuerSignatureAlgorithm().getName(),
                    x509v3CertificateBuilderHolder, issuerDN);

            logger.debug("Done with certificate signing  {} ", certificateGenerationInfo);

            return certificate;
        } catch (com.ericsson.oss.itpf.security.kaps.certificate.exception.CertificateSignatureException | com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException exception) {
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificateGenerator", "CertificateGenerationInfo",
                    "Unable to generate x509certificate for entity " + certificateGenerationInfo.getCAEntityInfo().getName());
            logger.error(ErrorMessages.SIGNATURE_GENERATION_FAILED, exception);
            throw new CertificateGenerationException(ErrorMessages.SIGNATURE_GENERATION_FAILED);
        } catch (com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException exception) {
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificateGenerator", "CertificateGenerationInfo",
                    "Exception while generating certificate signature for entity " + certificateGenerationInfo.getCAEntityInfo().getName());
            logger.error(ErrorMessages.SIGNATURE_GENERATION_FAILED, exception);
            throw new CertificateServiceException(ErrorMessages.SIGNATURE_GENERATION_FAILED);
        } catch (com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException invalidCertificateExtensionsException) {
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificateGenerator", "CertificateGenerationInfo",
                    "Provided certificate extensions are not valid for entity " + certificateGenerationInfo.getCAEntityInfo().getName());
            logger.error(ErrorMessages.INVALID_CERTIFICATE_EXTENSIONS, invalidCertificateExtensionsException);
            throw new InvalidCertificateExtensionsException(ErrorMessages.INVALID_CERTIFICATE_EXTENSIONS + invalidCertificateExtensionsException.getMessage());
        }
    }

    private X509v3CertificateBuilderHolder buildX509v3CertificateBuilderHolder(final CertificateGenerationInfo certificateGenerationInfo, final PublicKey publicKey, final List<Extension> extensions)
            throws UnsupportedCertificateVersionException {

        if (certificateGenerationInfo.getVersion() != CertificateVersion.V3) {
            throw new UnsupportedCertificateVersionException(ErrorMessages.UNSUPPORTED_CERTIFICATE_VERSION);
        }

        final X509v3CertificateBuilderHolder x509v3CertificateBuilderHolder = new X509v3CertificateBuilderHolder();

        final String subjectDN = certGenInfoParser.getSubjectDNFromCertGenerationInfo(certificateGenerationInfo);
        x509v3CertificateBuilderHolder.setSubjectDN(subjectDN);
        logger.debug("SubjectDN for the certificate to be generated {} ", subjectDN);

        final String issuerDN = certGenInfoParser.getIssuerDNFromCertGenerationInfo(certificateGenerationInfo);
        x509v3CertificateBuilderHolder.setIssuerDN(issuerDN);
        logger.debug("IssuerDN for the certificate to be generated {} ", issuerDN);

        final BigInteger serialNumber = new BigInteger(serialNumberGenerator.generateSerialNumber());
        x509v3CertificateBuilderHolder.setSerialNumber(serialNumber);

        Date notBefore = dateUtil.getCurrentDate();
        if (certificateGenerationInfo.getSkewCertificateTime() != null) {
            notBefore = dateUtil.subtractDurationFromDate(notBefore, certificateGenerationInfo.getSkewCertificateTime());
        }
        x509v3CertificateBuilderHolder.setNotBefore(notBefore);

        final Date notAfter = dateUtil.addDurationToDate(notBefore, certificateGenerationInfo.getValidity());
        x509v3CertificateBuilderHolder.setNotAfter(notAfter);

        x509v3CertificateBuilderHolder.setSubjectPublicKey(publicKey);

        if (certificateGenerationInfo.isSubjectUniqueIdentifier()) {
            x509v3CertificateBuilderHolder.setSubjectUniqueIdentifier(certificateGenerationInfo.isSubjectUniqueIdentifier());
            x509v3CertificateBuilderHolder.setSubjectUniqueIdentifierValue(certificateGenerationInfo.getSubjectUniqueIdentifierValue());
        }
        if (certificateGenerationInfo.isIssuerUniqueIdentifier()) {
            x509v3CertificateBuilderHolder.setIssuerUniqueIdentifier(certificateGenerationInfo.isSubjectUniqueIdentifier());
        }

        final List<CertificateExtensionHolder> certificateExtensionHolders = extensionBuilder.getCertificateExtensionHolders(extensions);

        if (certificateExtensionHolders != null && !certificateExtensionHolders.isEmpty()) {
            x509v3CertificateBuilderHolder.setCertificateExtensionHolders(certificateExtensionHolders);
        }

        logger.debug("TBSCertificate prepared with information passed {} ", certificateGenerationInfo);

        return x509v3CertificateBuilderHolder;
    }
}
