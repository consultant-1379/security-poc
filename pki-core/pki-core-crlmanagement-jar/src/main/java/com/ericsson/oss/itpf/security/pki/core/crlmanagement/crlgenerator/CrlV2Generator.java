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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator;

import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.common.model.crl.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CRLInfoMapper;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.utils.DateUtil;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.builder.RevokedCertificatesInfoBuilder;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException;

/**
 * This class will generate a Version2 CRL for a CertificateAuthority , IssuerCertificate and its Associated CRLGenerationInfo
 *
 * @author xananer
 */
public class CrlV2Generator implements CrlGenerator {

    final String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

    @Inject
    DateUtil dateUtil;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    RevokedCertificatesInfoBuilder revokedCertificatesInfoBuilder;

    @Inject
    CRLInfoMapper cRLInfoMapper;

    @Inject
    Logger logger;

    @Inject
    X509CRLBuilder x509CRLBuilder;

    @Inject
    CertificateAuthorityModelMapper certificateAuthorityModelMapper;

    @Inject
    private SystemRecorder systemRecorder;

    @Override
    public CRLInfo generateCRL(final CertificateAuthority certificateAuthority, final Certificate issuerCertificate, final CrlGenerationInfo crlGenerationInfo) throws CRLServiceException,
            CRLGenerationException, InvalidCRLExtensionException, RevocationServiceException {

        logger.info("generateCRL method of CrlV2Generator class");

        final List<RevokedCertificatesInfo> revokedCertificatesInfoList = revokedCertificatesInfoBuilder.buildRevokedCertificateInfo(issuerCertificate);

        final CRLNumber cRLNumber = fetchCrlNumber(certificateAuthority, crlGenerationInfo);

        final X509CRL x509CRL = x509CRLBuilder.build(certificateAuthority, issuerCertificate, revokedCertificatesInfoList, crlGenerationInfo, cRLNumber);

        final CRLInfo crlInfo = buildCRLInfo(x509CRL, issuerCertificate, cRLNumber);

        final CRL crl = new CRL();
        try {
            crl.setX509CRLHolder(new X509CRLHolder(x509CRL));
        } catch (final CRLException e) {
            logger.debug("Error while creating CRLHolder ", e);
            logger.error("Error while creating CRLHolder {}" , e.getMessage());
            systemRecorder.recordError(
                    "PKI_CORE_CRL_MANAGEMENT.CRL_GENERATION_FAILURE",
                    ErrorSeverity.ERROR,
                    "CrlV2Generator",
                    "Generation of CRL",
                    "Error occured while converting X509CRLHolder to X509CRL during the generation of CRL for the CA certificate : " + certificateAuthority.getName() + ","
                            + issuerCertificate.getSerialNumber() + ".");
            throw new CRLGenerationException("Error while creating X509CRL" + e.getMessage());
        }
        crlInfo.setCrl(crl);
        logger.info("End of generateCRL method of CrlV2Generator class");
        return crlInfo;
    }

    /**
     * This Method will build the API model of CRLInfo for a given x509CRL , issuerCertificate and CRLNumber
     *
     * @param x509CRL
     * @param issuerCertificate
     * @return
     */
    private CRLInfo buildCRLInfo(final X509CRL x509CRL, final Certificate issuerCertificate, final CRLNumber cRLNumber) throws CRLGenerationException {
        final CRL cRL = new CRL();

        final CRLInfo crlInfo = new CRLInfo();
        crlInfo.setThisUpdate(x509CRL.getThisUpdate());
        try {
            cRL.setX509CRLHolder(new X509CRLHolder(x509CRL));
        } catch (final CRLException e) {
            logger.debug("Error while setting the CRL to the holder ", e);
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.INTERNAL_ERROR", ErrorSeverity.ERROR, "CrlV2Generator", "Generation of CRL",
                    "Internal error occured while building X509 CRL Holder for the CA certificate of CA with serial number " + issuerCertificate.getSerialNumber() + ".");
            throw new CRLGenerationException("Error while setting the CRL to the holder");
        }
        crlInfo.setCrlNumber(cRLNumber);
        crlInfo.setCrl(cRL);
        crlInfo.setStatus(CRLStatus.LATEST);
        crlInfo.setIssuerCertificate(issuerCertificate);
        crlInfo.setNextUpdate(x509CRL.getNextUpdate());

        return crlInfo;
    }

    /**
     * This method will generate the CRL number to be added to the extensions during a CRL Generation
     *
     * @param certificateAuthority
     * @param crlGenerationInfo
     * @return
     */
    private synchronized CRLNumber fetchCrlNumber(final CertificateAuthority certificateAuthority, final CrlGenerationInfo crlGenerationInfo) {
        final CRLNumber cRLNumber = new CRLNumber();
        cRLNumber.setCritical(crlGenerationInfo.getCrlExtensions().getCrlNumber().isCritical());
        final List<CRLInfo> cRLInfos = certificateAuthority.getCrlInfo();
        if (cRLInfos == null || cRLInfos.size() == 0) {
            cRLNumber.setSerialNumber(1);
            return cRLNumber;
        }
        final List<Integer> cRLNumbers = new ArrayList<>();
        for (final CRLInfo cRLInfo : cRLInfos) {
            cRLNumbers.add(cRLInfo.getCrlNumber().getSerialNumber());
        }
        cRLNumber.setSerialNumber(Collections.max(cRLNumbers) + 1);
        return cRLNumber;
    }

}
