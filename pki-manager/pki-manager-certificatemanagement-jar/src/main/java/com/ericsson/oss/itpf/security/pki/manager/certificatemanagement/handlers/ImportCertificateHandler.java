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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers;

import java.security.cert.CertificateException;

import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;


import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.ReIssueType;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.CAReIssueInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.CertificatemanagementEserviceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.CAEntityCertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ImportCertificatePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAHierarchyPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CAReIssueType;

/**
 * This class is for handling the import certificate request for external root ca
 *
 * @author tcschdy
 *
 */
public class ImportCertificateHandler {

    @Inject
    CertificatemanagementEserviceProxy certificatemanagementEserviceProxy;

    @Inject
    CAEntityCertificateManager caEntityCertificateManager;

    @Inject
    CAHierarchyPersistenceHandler caHierarchyPersistenceHandler;

    @Inject
    ImportCertificatePersistenceHandler importCertificatePersistenceHandler;

    @Inject
    CARenewHandler caRenewHandler;

    @Inject
    CARekeyHandler caRekeyHandler;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method is used for handling the import certificate request for the certificate signed by external root ca
     *
     * @param caName
     *            name of the CA entity for which certificate needs to be imported.
     * @param x509Certificate
     *            X509Certificate object containing certificate data.
     * @param enableRFCValidation
     *            flag to enable RFC validations on the provided certificate
     * @param caReIssueType
     *            type that specifies re issue need to be done for Sub CAs of Root CA
     * @throws AlgorithmNotFoundException
     *             This exception is thrown if the given algorithm is not supported/not present in the database ,in case of CertificateImport/ CertificateGeneration for Re-issue of child CA's of
     *             imported CA
     * @throws CANotFoundException
     *             This exception is thrown if the given CA is not present in the database
     * @throws CertificateGenerationException
     *             This exception is thrown to indicate that an exception has occurred during certificate generation during Re-issue of child CA's of imported CA
     * @throws CertificateNotFoundException
     *             This exception is thrown when CA does not have Active Certificate to revoke during Re-issue of child CA's of imported CA
     * @throws CertificateServiceException
     *             This exception is thrown to indicate any internal database errors or any unconditional exceptions during Root CA certificate import signed by external CA and also during Re-issue of
     *             child CA's of imported CA
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain is expired.
     * @throws InvalidCAException
     *             This exception is thrown when the given CA is not having a valid state during certificate import
     * @throws IssuerCertificateRevokedException
     *             This exception is thrown if the Issuer certificate is already revoked during Re-issue of child CA's of imported CA
     * @throws InvalidEntityException
     *             This exception is thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             This exception is thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws InvalidOperationException
     *             This exception is thrown when the given CA is not root CA.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     * @throws RootCertificateRevocationException
     *             Thrown if Root CA certificate need to be revoked.
     * @throws RevocationServiceException
     *             Thrown when there is any internal error like any internal database failures during the revocation.
     */
    public void importCertificate(final String caName, final X509Certificate x509Certificate, final boolean enableRFCValidation, final CAReIssueType caReIssueType) throws AlgorithmNotFoundException,
            CANotFoundException, CertificateGenerationException, CertificateNotFoundException, CertificateServiceException, ExpiredCertificateException, InvalidCAException,
            IssuerCertificateRevokedException, InvalidEntityException, InvalidEntityAttributeException, InvalidInvalidityDateException, InvalidOperationException, RevokedCertificateException,
            RootCertificateRevocationException, RevocationServiceException {

        try {

            logger.info("Importing certificate for the CA  {} ", caName);

            importCertificatePersistenceHandler.storeCertificate(caName, x509Certificate);

            importCertificatePersistenceHandler.updateIssuerCAandCertificate(caName, x509Certificate);

            // core api is called to store the root certificate signed by external CA in the pki system
            logger.info("Calling importCertificate of pkicore : {} ", caName);
            certificatemanagementEserviceProxy.getCoreCertificateManagementService().importCertificate(caName, x509Certificate);

            logger.info("Reissuing certificate for the CA hierarchy after import {} ", caName);
            if (CAReIssueType.NONE != caReIssueType) {
                reIssueRootCAHierarchy(caName, caReIssueType);
            }

            systemRecorder.recordSecurityEvent("PKIManager.CertificateManagement", "ImportCertificateHandler", "Imported certificate for root ca : " + caName,
                    "CERTIFICATEMANAGEMENT.IMPORT_CERTIFICATE", ErrorSeverity.INFORMATIONAL, "SUCCESS");

        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException
                | com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException | EntityServiceException | PersistenceException exception) {
            logger.error(ErrorMessages.INTERNAL_ERROR, exception.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR + exception);
        } catch (CertificateException certificateException) {
            logger.error(ErrorMessages.ERROR_WHILE_IMPORT_CERT);
            throw new CertificateGenerationException(ErrorMessages.ERROR_WHILE_IMPORT_CERT, certificateException);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException entityNotFoundException) {
            logger.error(ErrorMessages.ENTITY_NOT_FOUND, entityNotFoundException.getMessage());
            throw new CANotFoundException(ErrorMessages.ENTITY_NOT_FOUND + entityNotFoundException);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCAException invalidCAException) {
            logger.error(ErrorMessages.INACTIVE_CA, invalidCAException.getMessage());
            throw new com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException(ErrorMessages.INACTIVE_CA, invalidCAException);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException invalidCertificateException) {
            logger.error(ErrorMessages.INVALID_CERTIFICATE, invalidCertificateException.getMessage());
            throw new com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException(ErrorMessages.INVALID_CERTIFICATE, invalidCertificateException);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidOperationException invalidOperationException) {
            logger.error(ErrorMessages.NOT_ROOT_CA, invalidOperationException.getMessage());
            throw new InvalidOperationException(ErrorMessages.NOT_ROOT_CA, invalidOperationException);
        }

    }

    private void reIssueRootCAHierarchy(final String caName, final CAReIssueType caReIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException,
            CertificateNotFoundException, CertificateServiceException, EntityServiceException, ExpiredCertificateException, InvalidCAException, IssuerCertificateRevokedException,
            InvalidEntityException, InvalidEntityAttributeException, InvalidInvalidityDateException, InvalidOperationException, RevokedCertificateException, RootCertificateRevocationException,
            RevocationServiceException {

        final List<String> childCAs = caHierarchyPersistenceHandler.getSubCANames(caName);

        switch (caReIssueType) {
        case RENEW_SUB_CAS:
            renewHierarchy(childCAs);
            break;
        case RENEW_SUB_CAS_WITH_REVOCATION:
            renewHierarchyWithRevocation(childCAs);
            break;
        case REKEY_SUB_CAS:
            reKeyHierarchy(childCAs);
            break;
        case REKEY_SUB_CAS_WITH_REVOCATION:
            reKeyHierarchyWithRevocation(childCAs);
            break;
        default:
            throw new InvalidOperationException("Invalid CA Reissue type");
        }
    }

    private void renewHierarchy(final List<String> childCAs) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException {

        for (final String caData : childCAs) {
            caEntityCertificateManager.renewCertificate(caData, ReIssueType.CA_WITH_ALL_CHILD_CAS);
        }
    }

    private void renewHierarchyWithRevocation(final List<String> childCAs) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateNotFoundException,
            CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException,
            InvalidInvalidityDateException, IssuerCertificateRevokedException, RevocationServiceException, RevokedCertificateException, RootCertificateRevocationException {

        for (final String caData : childCAs) {
            final CAReIssueInfo caReIssueInfo = new CAReIssueInfo();
            caReIssueInfo.setInvalidityDate(Calendar.getInstance().getTime());
            caReIssueInfo.setRevocationReason(RevocationReason.UNSPECIFIED);
            caReIssueInfo.setName(caData);
            caEntityCertificateManager.renewCertificate(caReIssueInfo, ReIssueType.CA_WITH_ALL_CHILD_CAS);
        }
    }

    private void reKeyHierarchy(final List<String> childCAs) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException, RevokedCertificateException {

        for (final String caData : childCAs) {
            caEntityCertificateManager.rekeyCertificate(caData, ReIssueType.CA_WITH_ALL_CHILD_CAS);
        }
    }

    private void reKeyHierarchyWithRevocation(final List<String> childCAs) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateNotFoundException,
            CertificateServiceException, ExpiredCertificateException, IssuerCertificateRevokedException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException,
            InvalidProfileAttributeException, InvalidInvalidityDateException, RevokedCertificateException, RootCertificateRevocationException, RevocationServiceException {

        for (final String caData : childCAs) {
            final CAReIssueInfo caReIssueInfo = new CAReIssueInfo();
            caReIssueInfo.setInvalidityDate(Calendar.getInstance().getTime());
            caReIssueInfo.setRevocationReason(RevocationReason.UNSPECIFIED);
            caReIssueInfo.setName(caData);
            caEntityCertificateManager.rekeyCertificate(caReIssueInfo, ReIssueType.CA_WITH_ALL_CHILD_CAS);
        }
    }

}
