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

import java.util.ArrayList;
import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.CertificateManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.EntityCertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.log.annotation.ErrorLogAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.common.validator.OtpValidator;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOTPException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.annotation.InstrumentationAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricGroup;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

@Profiled
@Stateless
@EServiceQualifier("1.0.0")
@ErrorLogAnnotation()
public class EntityCertificateManagementServiceBean implements EntityCertificateManagementService {

    @Inject
    Logger logger;

    @Inject
    EntityCertificateManager entityCertificateManager;

    @Inject
    OtpValidator otpvalidator;

    @Inject
    CertificateManagementAuthorizationManager certificateManagementAuthorizationManager;

    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYCERTIFICATEMGMT, metricType = MetricType.GENERATE)
    public Certificate generateCertificate(final String entityName, final CertificateRequest certificateRequest) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException, InvalidEntityException,
            InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.ENTITY);

        logger.info("generating certificate for Entity {} with CSR", entityName);

        return entityCertificateManager.generateCertificate(entityName, certificateRequest, RequestType.NEW);
    }

    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYCERTIFICATEMGMT, metricType = MetricType.GENERATE)
    public Certificate generateCertificate(final String entityName, final CertificateRequest certificateRequest, final String otp) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException, InvalidEntityException,
            InvalidEntityAttributeException, InvalidProfileAttributeException, OTPExpiredException, InvalidOTPException, RevokedCertificateException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.ENTITY);

        logger.info("generating certificate with otp validation for Entity {} with CSR", entityName);

        if (!otpvalidator.isOtpValid(entityName, otp)) {
            logger.error("Invalid OTP. OTP does not match for the Entity {}", entityName);
            throw new InvalidOTPException("Invalid OTP. OTP does not match for the Entity " + entityName);
        }
        return entityCertificateManager.generateCertificate(entityName, certificateRequest, RequestType.NEW);
    }

    @Override
    public List<Certificate> listCertificates(final String entityName, final CertificateStatus... status) throws CertificateNotFoundException, CertificateServiceException, EntityNotFoundException,
            InvalidEntityAttributeException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);

        logger.info("retrieving certificates of Entity {}", entityName);

        return entityCertificateManager.listCertificates(entityName, status);
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
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYCERTIFICATEMGMT, metricType = MetricType.GENERATE)
    public KeyStoreInfo generateCertificate(final String entityName, final char[] password, final KeyStoreType keyStoreType) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.CREATE, EntityType.ENTITY);

        logger.info("Generating certificate and keys for Entity {} ", entityName);

        return entityCertificateManager.generateKeyStore(entityName, password, keyStoreType, RequestType.NEW);

    }

    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYCERTIFICATEMGMT, metricType = MetricType.RENEW)
    public Certificate renewCertificate(final String entityName, final CertificateRequest certificateRequest) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException, InvalidEntityException,
            InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.ENTITY);

        logger.info("Regenerating certificate for Entity {} with CSR", entityName);

        return entityCertificateManager.generateCertificate(entityName, certificateRequest, RequestType.RENEW);
    }

    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYCERTIFICATEMGMT, metricType = MetricType.REKEY)
    public KeyStoreInfo reKeyCertificate(final String entityName, final char[] password, final KeyStoreType keyStoreType) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.ENTITY);

        logger.info("Regenerating certificate and keys for Entity {} ", entityName);

        return entityCertificateManager.generateKeyStore(entityName, password, keyStoreType, RequestType.REKEY);

    }

    @Override
    public CertificateChain getCertificateChain(final String entityName) throws CertificateServiceException, InvalidCAException, InvalidCertificateStatusException, InvalidEntityException,
            InvalidEntityAttributeException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);

        logger.debug("Retrieving certificate chain for Entity {} ", entityName);

        return entityCertificateManager.getCertificateChain(entityName, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE).get(0);

    }

    @Override
    public List<CertificateChain> getCertificateChainList(final String entityName, final CertificateStatus... certificateStatus) throws CertificateServiceException, InvalidCAException,
            InvalidCertificateStatusException, InvalidEntityException, InvalidEntityAttributeException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);

        logger.debug("Retrieving certificate chain for Entity {} ", entityName);

        return entityCertificateManager.getCertificateChain(entityName, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, certificateStatus);

    }

    public List<Certificate> getTrustCertificates(final String entityName) throws CertificateServiceException, EntityNotFoundException, ExternalCredentialMgmtServiceException, InvalidCAException,
            InvalidEntityAttributeException, ProfileNotFoundException {

        certificateManagementAuthorizationManager.authorizeGetTrustCertificates();

        logger.info("getting trusted certificates of Entity {}", entityName);

        return entityCertificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
    }

    @Override
    public void publishCertificate(final String entityName) throws CertificateServiceException, EntityNotFoundException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.ENTITY);
        entityCertificateManager.publishCertificate(entityName);
    }

    @Override
    public void unPublishCertificate(final String entityName) throws CertificateServiceException, EntityNotFoundException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.UPDATE, EntityType.ENTITY);
        entityCertificateManager.unPublishCertificate(entityName);
    }

    @Override
    public boolean isValidCertificate(final String entityName, final String serialNumber, final String issuerDN) throws CertificateServiceException,
            EntityNotFoundException, InvalidEntityAttributeException {

        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);
        return entityCertificateManager.isValidCertificate(entityName, serialNumber, issuerDN);
    }

    @Override
    public boolean isCertificateExist(final String subjectDN, final String serialNumber, final String issuerDN) throws CertificateServiceException {
        certificateManagementAuthorizationManager.authorizeCertificateMgmtOperations(ActionType.READ, EntityType.ENTITY);
        return entityCertificateManager.isCertificateExist(subjectDN, serialNumber, issuerDN);
    }

}
