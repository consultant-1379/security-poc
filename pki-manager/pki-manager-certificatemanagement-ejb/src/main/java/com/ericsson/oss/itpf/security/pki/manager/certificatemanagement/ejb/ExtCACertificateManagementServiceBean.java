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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.ejb;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ExtCACertificateManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.ExtCACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.ejb.utility.CertificateManagementUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.ExtCAEntityManager;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.log.annotation.ErrorLogAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCACRLsExistException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;

@Profiled
@Stateless
@EServiceQualifier("1.0.0")
@ErrorLogAnnotation()
public class ExtCACertificateManagementServiceBean implements ExtCACertificateManagementService {

    @Inject
    Logger logger;

    @Inject
    ExtCAEntityManager extCAEntityCertificateManager;

    @Inject
    private ExtCACertificateManagementAuthorizationManager extCACertificateManagementAuthorizationManager;

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    CertificateManagementUtility certificateManagementUtility;

    @Override
    public List<Certificate> listCertificates(final String extCAName, final CertificateStatus... certificateStatus) {

        List<Certificate> listOfCertificates = new ArrayList<>();
        try {
            extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.READ);
            boolean isExpiredStatusFound = false;
            for (CertificateStatus state : certificateStatus) {
                if (CertificateStatus.EXPIRED == state) {
                    isExpiredStatusFound = true;
                    break;
                }
            }
            listOfCertificates = extCAEntityCertificateManager.listCertificates(extCAName, certificateStatus);
            if (isExpiredStatusFound) {
                return listOfCertificates;
            }

        } catch (final MissingMandatoryFieldException e) {
            throw new EntityNotFoundException(e.getMessage(), e);
        }
        return certificateManagementUtility.removeExpiredCertificates(listOfCertificates);
    }

    @Override
    public List<Certificate> listCertificates_v1(final String entityName, final CertificateStatus... status) throws CertificateServiceException, EntityNotFoundException,
            InvalidEntityAttributeException {
        List<Certificate> listOfCertificates = new ArrayList<>();

        try {
            listOfCertificates = listCertificates(entityName, status);
        } catch (final CertificateNotFoundException certificateNotFoundException) {
            logger.error("Exception in listing certificates : {}", certificateNotFoundException.getMessage());
            logger.debug("Exception in listing certificates : {}", certificateNotFoundException);
        }
        return listOfCertificates;
    }

    @Override
    public void importCertificate(final String extCAName, final X509Certificate x509Certificate, final boolean enableRFCValidation) throws CertificateFieldException, CertificateNotFoundException,
            ExternalCAAlreadyExistsException, ExternalCANotFoundException, ExternalCredentialMgmtServiceException, MissingMandatoryFieldException {
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.CREATE);
        logger.debug("External CA import with Chain is Started");
        extCAEntityCertificateManager.importCertificate(extCAName, x509Certificate, enableRFCValidation);
        logger.debug("External CA import with Chain is Completed");
    }

    @Override
    public void forceImportCertificate(final String extCAName, final X509Certificate x509Certificate, final boolean enableRFCValidation) throws CertificateFieldException,
            ExternalCAAlreadyExistsException, ExternalCredentialMgmtServiceException, MissingMandatoryFieldException {
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.CREATE);
        logger.debug("External CA import for single certificate is Started");
        extCAEntityCertificateManager.forceImportCertificate(extCAName, x509Certificate, enableRFCValidation);
        logger.debug("External CA import for single certificate is Completed");
    }

    @Override
    public void remove(final String extCAName) throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCAInUseException, ExternalCACRLsExistException,
            ExternalCredentialMgmtServiceException {
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.DELETE);
        logger.debug("External CA Entity Delete is Started");
        extCAEntityCertificateManager.removeCertificate(extCAName);
        logger.debug("External CA Entity Delete is Completed");
    }

    @Override
    public List<X509Certificate> exportCertificate(final String extCAName, final String serialNumber, final boolean chain) throws CertificateNotFoundException, ExternalCANotFoundException,
            ExternalCredentialMgmtServiceException, MissingMandatoryFieldException {
        final List<X509Certificate> chainCerts = new ArrayList<>();
        extCACertificateManagementAuthorizationManager.authorizeExtCACertificateMgmtOperations(ActionType.EXPORT);
        logger.debug("External CA Export certificate is Started");
        chainCerts.add(extCAEntityCertificateManager.getExternalCACertificate(extCAName, serialNumber));
        logger.debug("External CA Export certificate is completed");
        return chainCerts;
    }
}
