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
package com.ericsson.oss.itpf.security.pki.manager.revocation.event.handler;

import java.io.IOException;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;

import javax.ejb.Asynchronous;
import javax.ejb.EJB;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.w3c.dom.Document;


import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationResponse;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.common.util.DateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.*;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.RequestHandlerUtility;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.SignedResponseBuilder;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CertificateManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.RevocationManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.revocation.event.publisher.RevocationServiceResponsePublisher;
import com.ericsson.oss.itpf.security.pki.manager.revocation.model.mapper.CertificateIdentifierModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.revocation.model.mapper.RevocationReasonTypeModelMapper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceRequest;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceResponse;

/**
 * This class is used to handle the revocation service request sent
 * 
 * @author tcsramc
 *
 */
public class RevocationServiceRequestHandler {

    @EJB
    RevocationManagementLocalService revocationManagementLocalService;

    @Inject
    RevocationServiceResponsePublisher revocationServiceResponsePublisher;

    @Inject
    RevocationReasonTypeModelMapper revocationReasonTypeMapper;

    @Inject
    CertificateIdentifierModelMapper certificateIdentifierModelMapper;

    @Inject
    SignedResponseBuilder signedResponseBuilder;

    @Inject
    RequestHandlerUtility requestHandlerUtility;

    @Inject
    Logger logger;

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    @EJB
    CertificateManagementLocalService certificateManagementLocalService;

    /**
     * This method validates and handles the revocation request that has been sent by CMP.
     * 
     * @param signedRevocationServiceRequest
     *            Which has been sent by CMP
     */
    @Asynchronous
    public void handle(final SignedRevocationServiceRequest signedRevocationServiceRequest) {
        RevocationResponse revocationResponse = null;
        RevocationRequest revocationRequest = null;

        try {

            final Document document = requestHandlerUtility.loadAndValidateRequest(signedRevocationServiceRequest.getRevocationServiceRequest());
            final X509Certificate requestSignerCertificate = JaxbUtil.getX509CertificateFromDocument(document);
            certificateManagementLocalService.validateCertificateChain(requestSignerCertificate);
            revocationRequest = (RevocationRequest) JaxbUtil.getObject(document, RevocationRequest.class);
            revokeCertificate(revocationRequest);

            revocationResponse = new RevocationResponse().setRevoked(true).setSubjectName(revocationRequest.getSubjectName()).setTransactionID(revocationRequest.getTransactionId());
            publish(revocationResponse);
        } catch (final ExpiredCertificateException | RevokedCertificateException exception) {
            logger.debug("Error occured while revoking the certificate ", exception);
            logger.error("ERROR OCCURED WHILE REVOKING THE CERTIFICATE:", exception.getCause());
            revocationResponse = new RevocationResponse().setRevoked(true);
            if(revocationRequest != null){
                revocationResponse.setSubjectName(revocationRequest.getSubjectName()).setTransactionID(revocationRequest.getTransactionId());
            }
            publish(revocationResponse);
        } catch (final CredentialsManagementServiceException | DigitalSignatureValidationException | UnmarshalException exception) {
            logger.debug("Error occured while validating the request ", exception);
            logger.error("ERROR OCCURED WHILE VALIDATING THE REQUEST:", exception.getCause());
            systemRecorder.recordSecurityEvent("PKIMANAGER-CMPSERVICE", "PKIMANAGER-CMPSERVICE.UNMARSHALING", "FAILED TO UNMARSHAL REQUEST MESSAGE", "PKIMANAGER-CMPSERVICE.REVOCATION",
                    ErrorSeverity.CRITICAL, "FAILURE");
        } catch (final CertificateException certificateException) {
            logger.debug("Error occured while fetching certificate from certificate holder ", certificateException);
            logCustomError("ERROR OCCURED WHILE FETCHING CERTIFICATE FROM CERTIFICATE HOLDER", "PKIMANAGER_CMPSERVICE.CERTIFICATEVALIDATIONFAILED");

        } catch (final CertificateNotFoundException certificateNotFoundException) {
            logger.debug("Certificate not found ", certificateNotFoundException);
            logCustomError("CERTIFICATE NOT FOUND", "PKIMANAGER_CMPSERVICE.CERTIFICATEVALIDATIONFAILED");

        } catch (final IOException iOException) {
            logger.debug("Error occured while performing I/O operations ", iOException);
            logCustomError("ERROR OCCURED WHILE PERFORMING I/O OPERATIONS", "PKIMANAGER_CMPSERVICE.CERTIFICATEVALIDATIONFAILED");

        } catch (final CertificateServiceException certificateServiceException) {
            logger.debug("Error occured while converting data to model object ", certificateServiceException);
            logCustomError("ERROR OCCURED WHILE CONVERTING DATA TO MODEL OBJECT ", "PKIMANAGER_CMPSERVICE.DATATOMODELCONVERSIONFAILED");

        } catch (final InvalidCAException invalidCAException) {
            logger.debug("Issuer certificate is revoked/expired ", invalidCAException);
            logCustomError("ISSUER CERTIFICATE IS REVOKED/EXPIRED ", "PKIMANAGER_CMPSERVICE.CERTIFICATEVALIDATIONFAILED");
        } catch (Exception exception) {
            logger.debug("Error occured while revoking the certificate ", exception);
            logger.error("ERROR OCCURED WHILE REVOKING THE CERTIFICATE:", exception.getCause());
            revocationResponse = new RevocationResponse().setRevoked(false);
            if(revocationRequest != null){
                revocationResponse.setSubjectName(revocationRequest.getSubjectName()).setTransactionID(revocationRequest.getTransactionId());
            }
            publish(revocationResponse);
        }
    }

    private void publish(final RevocationResponse revocationResponse) {
        try {
            final byte[] signedXMLData = signedResponseBuilder.buildSignedRevocationResponse(revocationResponse);
            final SignedRevocationServiceResponse signedRevocationServiceResponse = new SignedRevocationServiceResponse();
            signedRevocationServiceResponse.setRevocationServiceResponse(signedXMLData);
            revocationServiceResponsePublisher.publish(signedRevocationServiceResponse);
        } catch (final DigitalSigningFailedException digitalSigningFailedException) {
            logger.debug("Failed to sign the response message ", digitalSigningFailedException);
            logCustomError("FAILED TO SIGN THE RESPONSE MESSAGE", "PKIMANAGER_CMPSERVICE.DIGITALSIGININGFAILED");

        } catch (final CredentialsManagementServiceException credentialsManagementServiceException) {
            logger.debug("Internal error occured in credential manager while signing repsonse message ", credentialsManagementServiceException);
            logCustomError("INTERNAL ERROR OCCURED IN CREDENTIAL MANAGER WHILE SIGNING RESPONSE MESSAGE", "PKIMANAGER_CMPSERVICE.CREDENTIALMANAGERERROR");

        } catch (final MarshalException marshalException) {
            logger.debug("Error occured while marshaling data ", marshalException);
            logCustomError("ERROR OCCURED WHILE MARSHALING DATA", "PKIMANAGER_CMPSERVICE.MARSHALLINGFAILED");
        }
    }

    private void revokeCertificate(final RevocationRequest revocationRequest) throws ExpiredCertificateException, RevokedCertificateException {
        Date invalidityDate = null;

        final CertificateIdentifier certificateIdentifier = certificateIdentifierModelMapper.toCertificateIdentifier(revocationRequest);
        try {
            final String dateinStringFormat = revocationRequest.getInvalidityDate();
            invalidityDate = DateUtility.convertUTCtoSystemDate(dateinStringFormat);
        } catch (final ParseException parseException) {
            logger.error("Date can not parsed to UTC hence returning local time");
            logger.debug("Exception stacktrace ", parseException);
            invalidityDate = new Date();
        }
        final RevocationReason revocationReason = revocationReasonTypeMapper.fromModel(revocationRequest);
        final String transactionID = revocationRequest.getTransactionId();
        final String senderName = revocationRequest.getSubjectName();

        revocationManagementLocalService.revokeCertificate(certificateIdentifier, invalidityDate, revocationReason, transactionID, senderName);

    }

    private void logCustomError(final String errorMessage, final String eventType) {
        logger.error(errorMessage);
        systemRecorder.recordSecurityEvent("PKIMANAGER_CMP_SECURECOMMUNICATION", "PKIMANAGER_CMP_SECURECOMMUNICATION.CMPServiceRequestProcessor", errorMessage, eventType, ErrorSeverity.CRITICAL,
                "FAILURE");
    }

}
