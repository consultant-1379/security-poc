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
import java.util.Set;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.ReIssueType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.CertificateManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.CAReIssueInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.ExtCAIssuerCertificateChainBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.ejb.utility.CertificateManagementUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.CAEntityCertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.ImportCertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.log.annotation.ErrorLogAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ExtCACertificatePersistanceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.InvalidInvalidityDateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerCertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RootCertificateRevocationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.annotation.InstrumentationAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricGroup;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CAReIssueType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CertificateInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.ValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CAValidationInfo;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ItemType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.builders.ValidateItemBuilder;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils.ValidationServiceUtils;

@Profiled
@Stateless
@EServiceQualifier("1.0.0")
@ErrorLogAnnotation()
public class CACertificateManagementServiceBean implements CACertificateManagementService {

    @Inject
    Logger logger;

    @Inject
    CAEntityCertificateManager caEntityCertificateManager;

    @Inject
    CertificateManagementAuthorizationManager certificateManagementAuthorizationManager;

    @Inject
    ValidationServiceUtils validationServiceUtils;

    @Inject
    ValidationService validationService;

    @Inject
    ImportCertificateManager importCertificateManager;

    @Inject
    ExtCAIssuerCertificateChainBuilder extCAIssuerCertificateChainBuilder;

    @Inject
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    CertificateManagementUtility certificateManagementUtility;

    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.CACERTIFICATEMGMT, metricType = MetricType.GENERATE)
    public Certificate generateCertificate(final String caEntityName) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.CA_ENTITY);
        logger.debug("Generating certificate for CAEntity {}", caEntityName);

        return caEntityCertificateManager.generateCertificate(caEntityName);

    }

    @Override
    public List<Certificate> listCertificates(final String entityName, final CertificateStatus... status) throws CertificateNotFoundException, CertificateServiceException, EntityNotFoundException,
            InvalidEntityAttributeException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);

        logger.debug("Retrieving certificates of CAEntity {} with status {}", entityName, new Object[] { status });
        boolean isExpiredStatusFound = false;
        for (CertificateStatus state : status) {
            if (CertificateStatus.EXPIRED == state) {
                isExpiredStatusFound = true;
                break;
            }
        }
        List<Certificate> listOfCertificates = caEntityCertificateManager.listCertificates(entityName, status);
        if (isExpiredStatusFound) {
            return listOfCertificates;
        }
        return certificateManagementUtility.removeExpiredCertificates(listOfCertificates);
    }

    @Override
    public List<Certificate> listCertificates_v1(final String entityName, final CertificateStatus... status) throws CertificateServiceException, EntityNotFoundException,
            InvalidEntityAttributeException {
        List<Certificate> listOfCertificates = new ArrayList<>();

        try {
            listOfCertificates = listCertificates(entityName, status);
        } catch (CertificateNotFoundException certificateNotFoundException) {
            logger.error("Exception in listing certificates : {}", certificateNotFoundException.getMessage());
            logger.debug("Exception in listing certificates : {}", certificateNotFoundException);
        }
        return listOfCertificates;
    }

    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.CACERTIFICATEMGMT, metricType = MetricType.RENEW)
    public void renewCertificate(final String entityName, final ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException,
            RevokedCertificateException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);

        logger.debug("Renewing certificate for CAEntity {}", entityName);

        caEntityCertificateManager.renewCertificate(entityName, reIssueType);

    }

    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.CACERTIFICATEMGMT, metricType = MetricType.REKEY)
    public void rekeyCertificate(final String entityName, final ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException,
            RevokedCertificateException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);
        logger.debug("Rekey for CAEntity {}", entityName);

        caEntityCertificateManager.rekeyCertificate(entityName, reIssueType);

    }

    @Override
    public PKCS10CertificationRequestHolder generateCSR(final String entityName, final boolean newKey) throws AlgorithmNotFoundException, CANotFoundException, CertificateRequestGenerationException,
            CertificateServiceException, InvalidCAException, InvalidEntityAttributeException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);

        logger.info("Exporting CSR in pki Manager started for CAEntity {}", entityName);

        final CAEntity caEntity = caEntityCertificateManager.getRootCAEntity(entityName);

        final CAValidationInfo caValidationInfo = new CAValidationInfo();
        caValidationInfo.setCaEntity(caEntity);
        caValidationInfo.setNewKey(newKey);

        final ValidateItem validateItem = (new ValidateItemBuilder()).setItem(caValidationInfo).setItemType(ItemType.GENERATE_CSR).setOperationType(OperationType.VALIDATE).build();

        validationService.validate(validateItem);

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = caEntityCertificateManager.generateCSR(entityName, newKey);

        logger.info("Exporting CSR in pki Manager done for CAEntity {}", entityName);

        return pkcs10CertificationRequestHolder;
    }

    @Override
    public PKCS10CertificationRequestHolder getCSR(final String caName) throws CANotFoundException, CertificateRequestGenerationException, CertificateServiceException, InvalidOperationException {
        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);
        logger.info("Get CSR in pki Manager started for CAEntity {}", caName);

        final CAEntity caEntity = caEntityCertificateManager.getRootCAEntity(caName);
        final CAValidationInfo caValidationInfo = new CAValidationInfo();
        caValidationInfo.setCaEntity(caEntity);
        caValidationInfo.setNewKey(true);

        final ValidateItem validateItem = (new ValidateItemBuilder()).setItem(caValidationInfo).setItemType(ItemType.GENERATE_CSR).setOperationType(OperationType.VALIDATE).build();

        validationService.validate(validateItem);

        final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = caEntityCertificateManager.getCSR(caName);

        logger.info("Get CSR in pki Manager done for CAEntity {}", caName);

        return pkcs10CertificationRequestHolder;
    }

    @Override
    public void publishCertificate(final String entityName) throws CANotFoundException, CertificateServiceException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);
        caEntityCertificateManager.publishCertificate(entityName);
    }

    @Override
    public void unPublishCertificate(final String entityName) throws CANotFoundException, CertificateServiceException {
        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);
        caEntityCertificateManager.unPublishCertificate(entityName);
    }

    @Override
    public List<CertificateChain> getCertificateChainList(final String entityName, final CertificateStatus... certificateStatus) throws CertificateServiceException, InvalidCAException,
            InvalidCertificateStatusException, InvalidEntityException, InvalidEntityAttributeException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);

        logger.debug("Retrieving certificate chain for CAEntity {} ", entityName);

        return caEntityCertificateManager.getCertificateChain(entityName, EntityType.CA_ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, certificateStatus);

    }

    @Override
    public List<Certificate> getCertificateChain(final String entityName) throws CertificateServiceException, InvalidCAException, InvalidEntityAttributeException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);

        logger.debug("Retrieving certificate chain for CAEntity {} ", entityName);

        return caEntityCertificateManager.getCertificateChain(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);

    }

    @Override
    public void renewCertificates(final Set<String> cANames) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, RevokedCertificateException {
        // TODO Auto-generated method stub

    }

    @Override
    public void importCertificate(final String caName, final X509Certificate x509Certificate, final boolean enableRFCValidation, final CAReIssueType caReIssueType) throws AlgorithmNotFoundException,
            CANotFoundException, CertificateGenerationException, CertificateNotFoundException, CertificateServiceException, ExpiredCertificateException, InvalidCAException,
            IssuerCertificateRevokedException, InvalidEntityException, InvalidEntityAttributeException, InvalidInvalidityDateException, InvalidOperationException, RevokedCertificateException,
            RootCertificateRevocationException, RevocationServiceException {
        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);
        //Validating whether Given CA is RootCA or not
        final CAEntity caEntity = caEntityCertificateManager.getRootCAEntity(caName);
        final CAValidationInfo caValidationInfo = new CAValidationInfo();
        caValidationInfo.setCaEntity(caEntity);
        caValidationInfo.setNewKey(true);
        final ValidateItem caValidateItem = (new ValidateItemBuilder()).setItem(caValidationInfo).setItemType(ItemType.GENERATE_CSR).setOperationType(OperationType.VALIDATE).build();

        validationService.validate(caValidateItem);

        final CACertificateValidationInfo caCertificateValidationInfo = new CACertificateValidationInfo();
        caCertificateValidationInfo.setCaName(caName);
        caCertificateValidationInfo.setCertificate(x509Certificate);
        caCertificateValidationInfo.setForceImport(false);

        final ValidateItem validateItem = validationServiceUtils
                .generateX509CertificateValidateItem(ItemType.X509CERTIFICATE, OperationType.VALIDATE, caCertificateValidationInfo, enableRFCValidation);
        validationService.validate(validateItem);

        //TODO: JIRA TORF-119830 - code improvement chain validation to be done during external CA import
        //To move the updateIssuerCertificateChain to MS4 code and move validateCertificateChain into validationService
        extCAIssuerCertificateChainBuilder.updateIssuerCertificateChain(extCACertificatePersistanceHandler.getIssuerX509Certificate(x509Certificate));

        extCACertificatePersistanceHandler.validateCertificateChain(extCACertificatePersistanceHandler.getIssuerX509Certificate(x509Certificate));

        importCertificateManager.importCertificate(caName, x509Certificate, enableRFCValidation, caReIssueType);

    }

    @Override
    public void forceImportCertificate(final String caName, final X509Certificate x509Certificate, final boolean enableRFCValidation, final CAReIssueType caReIssueType)
            throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateNotFoundException, CertificateServiceException, ExpiredCertificateException,
            InvalidCAException, IssuerCertificateRevokedException, InvalidEntityException, InvalidEntityAttributeException, InvalidInvalidityDateException, InvalidOperationException,
            RevokedCertificateException, RevocationServiceException, RootCertificateRevocationException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);

        //Validating whether Given CA is RootCA or not
        final CAEntity caEntity = caEntityCertificateManager.getRootCAEntity(caName);
        final CAValidationInfo caValidationInfo = new CAValidationInfo();
        caValidationInfo.setCaEntity(caEntity);
        caValidationInfo.setNewKey(true);
        final ValidateItem caValidateItem = (new ValidateItemBuilder()).setItem(caValidationInfo).setItemType(ItemType.GENERATE_CSR).setOperationType(OperationType.VALIDATE).build();
        validationService.validate(caValidateItem);

        final CACertificateValidationInfo caCertificateValidationInfo = new CACertificateValidationInfo();
        caCertificateValidationInfo.setCaName(caName);
        caCertificateValidationInfo.setCertificate(x509Certificate);
        caCertificateValidationInfo.setForceImport(true);

        final ValidateItem validateItem = validationServiceUtils
                .generateX509CertificateValidateItem(ItemType.X509CERTIFICATE, OperationType.VALIDATE, caCertificateValidationInfo, enableRFCValidation);
        validationService.validate(validateItem);

        //TODO: JIRA TORF-119830 - code improvement chain validation to be done during external CA import
        //To move the updateIssuerCertificateChain to MS4 code and move validateCertificateChain into validationService
        extCAIssuerCertificateChainBuilder.updateIssuerCertificateChain(extCACertificatePersistanceHandler.getIssuerX509Certificate(x509Certificate));

        extCACertificatePersistanceHandler.validateCertificateChain(extCACertificatePersistanceHandler.getIssuerX509Certificate(x509Certificate));

        importCertificateManager.importCertificate(caName, x509Certificate, enableRFCValidation, caReIssueType);

    }

    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.CACERTIFICATEMGMT, metricType = MetricType.REKEY)
    public void rekeyCertificate(final CAReIssueInfo caReIssueInfo, final ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateNotFoundException, CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException,
            InvalidProfileAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException, RevokedCertificateException, RevocationServiceException,
            RootCertificateRevocationException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);

        logger.debug("Rekey CA {} certificate with revocation, revocation reason {} , invalidity date {}, reIssueType {} ", caReIssueInfo.getName(), caReIssueInfo.getRevocationReason(),
                caReIssueInfo.getInvalidityDate(), reIssueType);

        caEntityCertificateManager.rekeyCertificate(caReIssueInfo, reIssueType);

    }

    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.CACERTIFICATEMGMT, metricType = MetricType.RENEW)
    public void renewCertificate(final CAReIssueInfo caReIssueInfo, final ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateNotFoundException, CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException,
            InvalidProfileAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException, RevokedCertificateException, RevocationServiceException,
            RootCertificateRevocationException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.CA_ENTITY);

        logger.debug("Renew CA {} certificate with revocation,  revocation reason {} , invalidity date {}, reIssueType {} ", caReIssueInfo.getName(), caReIssueInfo.getRevocationReason(),
                caReIssueInfo.getInvalidityDate(), reIssueType);

        caEntityCertificateManager.renewCertificate(caReIssueInfo, reIssueType);

    }

    @Override
    public void renewCertificates(final List<CAReIssueInfo> arg0) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateNotFoundException,
            CertificateServiceException, ExpiredCertificateException, InvalidCAException, RevokedCertificateException, RevocationServiceException, RootCertificateRevocationException {
        // TODO Auto-generated method stub

    }

    public List<CertificateInfo> listIssuedCertificates(final CACertificateIdentifier caCertificateIdentifier, final CertificateStatus... status) throws CANotFoundException,
            CertificateNotFoundException, CertificateServiceException, MissingMandatoryFieldException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);

        logger.info("Retrieving list of certificates Issued By CACertificateIdentifier : {} and  status : {}", caCertificateIdentifier, status);

        return caEntityCertificateManager.listIssuedCertificates(caCertificateIdentifier, status);
    }

    @Override
    public List<CertificateInfo> listIssuedCertificates(final DNBasedCertificateIdentifier dnBasedIdentifier, final CertificateStatus... status) throws CANotFoundException,
            CertificateNotFoundException, CertificateServiceException, MissingMandatoryFieldException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.CA_ENTITY);

        logger.info("Retrieving list of certificates Issued By DNBasedCertificateIdentifier : {} and  status : {}", dnBasedIdentifier, status);

        return caEntityCertificateManager.listIssuedCertificates(dnBasedIdentifier, status);
    }
}
