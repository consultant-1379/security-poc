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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Date;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.CertificateStatusUpdateFailedException;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.CRLHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExternalCRLMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * 
 * This class is used to update CA certificate status to revoked, which are issued by ExternalCA and whose serial number is found in the ExternalCA CRL
 * 
 * @author tcsviku
 *
 */
public class ExternalCACRLHandler {

    @Inject
    private Logger logger;

    @Inject
    private ExternalCRLMapper externalCRLMapper;

    @Inject
    private CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    private CRLHelper crlHelper;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method is to fetch ExternalCA CRL using CDPS url if accessible, otherwise check existing CRL from ExternalCRLInfo and update the status of certificate to REVOKE if its serial number is
     * found in CRL.
     * 
     * @throws CertificateServiceException
     *             to indicate any internal database errors or any unconditional exceptions.
     * @throws CertificateStatusUpdateFailedException
     *             when CertificateStatus update has failed.
     * @throws CRLServiceException
     *             when there is any internal error like database error during the generation and fetching of CRL.
     * @throws ExternalCANotFoundException
     *             when extCA is not found with the given name.
     * @throws ExternalCredentialMgmtServiceException
     *             in case of any internal database failures.
     * @throws ExternalCRLEncodedException
     *             to indicate an error at CRL encoding time.
     * @throws ExternalCRLNotFoundException
     *             to indicate that CRLs are not present for the corresponding entity.
     * @throws MissingMandatoryFieldException
     *             when the mandatory field is missed as part of the request.
     */
    public void externalCACRLHandle() throws CertificateServiceException, CertificateStatusUpdateFailedException, CRLServiceException, ExternalCANotFoundException,
            ExternalCredentialMgmtServiceException, ExternalCRLEncodedException, ExternalCRLNotFoundException, MissingMandatoryFieldException {
        logger.debug("Start of externalCACRLHandle method in ExternalCACRLHandler class");

        final List<CertificateData> certificates = certificatePersistenceHelper.getCertificatesIssuedByExternalCA();
        final Date currentDate = new Date();
        ExternalCRLInfo externalCRLInfo = null;
        for (CertificateData certificate : certificates) {

            externalCRLInfo = externalCRLMapper.toAPIFromModel(certificate.getIssuerCA().getCertificateAuthorityData().getExternalCrlInfoData());

            X509CRL x509Crl = null;
            try {

                x509Crl = crlHelper.getCRLFromExternalCDPS(externalCRLInfo.getUpdateURL());
            } catch (Exception e) {
                logger.debug("Unable to access ExternalCA CDPS URL of {}. Hence, fetching existing CRL from db ", certificate.getIssuerCA().getCertificateAuthorityData().getName(), e);
                systemRecorder.recordSecurityEvent("PKIMANAGER_CRL_MANAGEMENT", "ExternalCACRLHandler", "Unable to access External CA CDPS URL of "
                        + certificate.getIssuerCA().getCertificateAuthorityData().getName() + ".Hence, fetching existing CRL from db.", "PKIMANAGER_CRL_MANAGEMENT.EXTERNAL_CA_CRL_HANDLE",
                        ErrorSeverity.INFORMATIONAL, "SUCCESS");
                final X509CRLHolder x509CrlHolder = externalCRLInfo.getX509CRL();
                x509Crl = x509CrlHolder.retrieveCRL();
            }
            if (x509Crl.getNextUpdate().after(currentDate)) {

                final BigInteger sno = new BigInteger(certificate.getSerialNumber(), 16);
                final X509CRLEntry crlentry = x509Crl.getRevokedCertificate(sno);
                if (crlentry != null) {
                    certificatePersistenceHelper.updateCertificateStatusToRevoke(certificate.getSerialNumber());
                }
            } else {
                logger.debug("CRL for ExternalCA {} is expired", certificate.getIssuerCA().getCertificateAuthorityData().getName());
                systemRecorder.recordSecurityEvent("PKIMANAGER_CRL_MANAGEMENT", "ExternalCACRLHandler", "CRL for ExternalCA " + certificate.getIssuerCA().getCertificateAuthorityData().getName()
                        + " is expired.Hence, certificate status update not required.", "PKIMANAGER_CRL_MANAGEMENT.EXTERNAL_CA_CRL_HANDLE", ErrorSeverity.INFORMATIONAL, "SUCCESS");
            }
        }
        logger.debug("End of externalCACRLHandle method in ExternalCACRLHandler class");
    }
}