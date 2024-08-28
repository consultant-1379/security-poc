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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ir;

import java.io.IOException;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.EJB;
import javax.inject.Inject;
import javax.naming.InvalidNameException;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.*;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPRequest;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.MarshalException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.RequestHandler;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.er.ErrorResponseBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.exception.*;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.*;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.publisher.CMPServiceResponsePublisher;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.validator.IAKValidationException;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.validator.IAKValidator;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CertificateManagementLocalService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceResponse;

/**
 * This class is used for generating the CMP Response in the case where the CMPRequest is of type Initial Request and dispatching it to the CMP Service.
 * 
 * @author tcschdy
 * 
 */
public class InitializationRequestHandler implements RequestHandler {
    @EJB
    CertificateManagementLocalService certificateManagementLocalService;

    @Inject
    InitializationResponseBuilder initializationResponseBuilder;

    @Inject
    ErrorResponseBuilder failureResponseBuilder;

    @Inject
    CMPServiceResponsePublisher cMPServiceResponsePublisher;

    @Inject
    IAKValidator iakValidator;

    @Inject
    SignedResponseBuilder signedResponseBuilder;

    @Inject
    CMPCertificateManagementUtility cMPCertificateManagementUtility;

    @Inject
    EntityHandlerUtility entityHandlerUtility;

    @Inject
    Logger logger;

    @Override
    public void handle(final CMPRequest cMPRequest) throws CredentialsManagementServiceException, DigitalSigningFailedException, MarshalException {

        RequestMessage pKIRequestMessage = null;
        String transactionID = null;
        byte[] cMPRequestByteArray = null;
        transactionID = cMPRequest.getTransactionId();
        cMPRequestByteArray = cMPRequest.getCmpRequest();
        final boolean isSynchRequest = cMPRequest.getSyncRequest();
        String entityName = null;
        try {
            logger.info("Handling Initilization request from pki-ra for transaction id {}", transactionID);
            pKIRequestMessage = new RequestMessage(cMPRequestByteArray);
            
            entityName = entityHandlerUtility.getEntityName(pKIRequestMessage);
            logger.debug("Found entity with entity name [{}]",entityName);
            
            handleIR(pKIRequestMessage, transactionID, isSynchRequest, entityName, cMPRequest.getIssuerName());

        } catch (final AlgorithmNotFoundException | CertificateServiceException | EntityNotFoundException | EntityServiceException | IAKValidationException | ResponseEventBuilderException | IOException
                | InvalidNameException | RevocationResponseBuilderException exception) {
            handleException(transactionID, pKIRequestMessage, exception, isSynchRequest, entityName, cMPRequest.getIssuerName());

        }

    }

    private void handleIR(final RequestMessage pKIRequestMessage, final String transactionID, final boolean isSynchRequest, final String entityName, final String issuerName)
            throws CredentialsManagementServiceException, DigitalSigningFailedException, IAKValidationException, IOException, MarshalException, ResponseEventBuilderException,
            RevocationResponseBuilderException {
        CMPResponse cMPResponse;
        IPResponseMessage ipResponseMessage = null;
        byte[] signedInitialResponse;

        logger.info("Handling Initilization request from pki-ra for transaction id {}, Entity Name {}, is SYNC Request {} and is IAK Based {}", transactionID, entityName, isSynchRequest, pKIRequestMessage.isMacBased() );

        if (pKIRequestMessage.isMacBased()) {
            iakValidator.verifyPasswordBasedMac(entityName, pKIRequestMessage);
            logger.debug("IAK verification is successful for entity [{}]",entityName);
        }

        try {
            ipResponseMessage = buildResponseMessage(pKIRequestMessage, transactionID, entityName);
            cMPResponse = ResponseBuilderUtility.buildResponseEvent(ipResponseMessage, transactionID, isSynchRequest, issuerName);
            signedInitialResponse = signedResponseBuilder.buildSignedCMPResponse(cMPResponse);
            logger.info("Built Initial Response Message and is dispatched onto the queue for senderName:{} and transactionId:{}", pKIRequestMessage.getSenderName(),
                    pKIRequestMessage.getBase64TransactionID());
            
        } catch (final IOException ioException) {
            logger.warn("Unable to parse bytes sent from Queue for CMPService for TransactionId : {} ", pKIRequestMessage.getBase64TransactionID());
            logger.debug("Exception StackTrace: ", ioException);
            cMPResponse = ResponseBuilderUtility.buildDefaultResponseEventForUnknownError(ioException.getMessage(), transactionID, isSynchRequest, issuerName);
            signedInitialResponse = signedResponseBuilder.buildSignedCMPResponse(cMPResponse);
        }
        dispatch(signedInitialResponse);

    }

    private IPResponseMessage buildResponseMessage(final RequestMessage pKIRequestMessage, final String transactionID, final String entityName) throws ResponseEventBuilderException {
        IPResponseMessage ipResponseMessage = null;

        try {

            final CertificateRequest certificateRequest = CertificateRequestUtility.generateCSRfromRequestMessage(pKIRequestMessage);

            final X509Certificate x509UserCertificate = cMPCertificateManagementUtility.getUserCertificate(entityName, certificateRequest);

            final List<X509Certificate> x509ExtraCertificates = cMPCertificateManagementUtility.getCertificateChain(entityName);

            final List<X509Certificate> x509trustedCertificates = cMPCertificateManagementUtility.getTrustCertificates(entityName);

            ipResponseMessage = initializationResponseBuilder.build(pKIRequestMessage, transactionID, x509UserCertificate, x509ExtraCertificates, x509trustedCertificates);

        } catch (final IOException iOException) {
            ExceptionHelper.throwResponseEventBuilderException(ErrorMessages.IO_EXCEPTION, iOException);

        } catch (final CertificateGenerationException certificateGenerationException) {
            ExceptionHelper.throwResponseEventBuilderException(ErrorMessages.NOT_ABLE_TO_GENERATE_CERTIFICATE, certificateGenerationException);

        } catch (final InvalidCertificateRequestException invalidCSRException) {
            ExceptionHelper.throwResponseEventBuilderException(ErrorMessages.INVALID_CSR, invalidCSRException);

        } catch (final InvalidEntityException invalidEntityException) {
            ExceptionHelper.throwResponseEventBuilderException(ErrorMessages.INVALID_ENTITY, invalidEntityException);

        } catch (final CertificateAlreadyExistsException certificateExistsException) {
            ExceptionHelper.throwResponseEventBuilderException(ErrorMessages.CERTIFICATE_ALREADY_GENERATED, certificateExistsException);

        } catch (final CertificateNotFoundException certificateNotFoundException) {
            ExceptionHelper.throwResponseEventBuilderException(ErrorMessages.CERTIFICATE_NOT_FOUND, certificateNotFoundException);

        } catch (final InvalidCAException invalidCAException) {
            ExceptionHelper.throwResponseEventBuilderException(ErrorMessages.INVALID_CA_NAME, invalidCAException);

        } catch (final ProfileNotFoundException profileNotFoundException) {
            ExceptionHelper.throwResponseEventBuilderException(ErrorMessages.NO_TRUST_PROFILE_PRESENT, profileNotFoundException);

        } catch (final CertificateServiceException certificateServiceException) {
            ExceptionHelper.throwResponseEventBuilderException(ErrorMessages.DB_EXCEPTION_AT_MANAGER, certificateServiceException);

        } catch (final EntityNotFoundException entityNotFoundException) {
            ExceptionHelper.throwResponseEventBuilderException(ErrorMessages.ENTITY_DOES_NOT_EXISTS, entityNotFoundException);
        }
        return ipResponseMessage;
    }

    private void handleException(final String transactionID, final RequestMessage pKIRequestMessage, final Throwable throwable, final boolean isSynchRequest, final String entityName,
            final String issuerName) throws CredentialsManagementServiceException, DigitalSigningFailedException, MarshalException {
        X509Certificate x509UserCertificate = null;
        CMPResponse cMPResponse = null;
        byte[] signedErrorResponse;

        String errorMessage = throwable.getMessage();
        if (errorMessage == null || errorMessage.isEmpty()) {
            errorMessage = ErrorMessages.UNEXPECTED_ERROR;
        }

        try {
            if (entityName != null) {
                final List<Certificate> certificatesFromDB = certificateManagementLocalService.getEntityCertificates(entityName);
                final Certificate userCertificate = certificatesFromDB.get(0);
                if (userCertificate != null) {
                    x509UserCertificate = userCertificate.getX509Certificate();
                }
            }

            final FailureResponseMessage failureResponseMessage = failureResponseBuilder.build(errorMessage, transactionID, pKIRequestMessage, x509UserCertificate);
            cMPResponse = ResponseBuilderUtility.buildResponseEvent(failureResponseMessage, transactionID, isSynchRequest, issuerName);
            signedErrorResponse = signedResponseBuilder.buildSignedCMPResponse(cMPResponse);
            logger.error(errorMessage);
            logger.error("Exception StackTrace {}", throwable);

        } catch (final IOException | CertificateException | PersistenceException exception) {
            cMPResponse = buildDefaultErrorMessage(transactionID, throwable, errorMessage, isSynchRequest, issuerName);
            signedErrorResponse = signedResponseBuilder.buildSignedCMPResponse(cMPResponse);
            logger.debug(exception.getMessage(), exception);
        } catch (final Exception exception) {
            cMPResponse = buildDefaultErrorMessage(transactionID, throwable, errorMessage, isSynchRequest, issuerName);
            signedErrorResponse = signedResponseBuilder.buildSignedCMPResponse(cMPResponse);
            logger.debug(exception.getMessage(), exception);
        }

        dispatch(signedErrorResponse);
    }

    private CMPResponse buildDefaultErrorMessage(final String transactionID, final Throwable throwable, final String errorMessage, final boolean isSynchRequest, final String issuerName) {
        logger.error(errorMessage);
        logger.debug("Exception StackTrace {}", throwable);
        final CMPResponse cMPResponse = ResponseBuilderUtility.buildDefaultResponseEventForUnknownError(errorMessage, transactionID, isSynchRequest, issuerName);
        return cMPResponse;
    }

    private void dispatch(final byte[] signedXMLData) {
        final SignedCMPServiceResponse signedCMPServiceResponse = new SignedCMPServiceResponse();
        if (signedXMLData != null) {
            signedCMPServiceResponse.setCmpResponse(signedXMLData);
            cMPServiceResponsePublisher.publish(signedCMPServiceResponse);
        }
    }

}
