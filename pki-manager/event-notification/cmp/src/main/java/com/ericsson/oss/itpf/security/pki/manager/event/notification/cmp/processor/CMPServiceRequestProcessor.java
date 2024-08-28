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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.processor;

import java.io.IOException;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.ejb.Asynchronous;
import javax.ejb.EJB;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.w3c.dom.Document;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPRequest;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.*;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.RequestHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.RequestHandlerUtility;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CertificateManagementLocalService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceRequest;

/**
 * This class is used to process the request that is recieved from CMP service over the queue
 * 
 * @author tcschdy
 * 
 */
public class CMPServiceRequestProcessor {
    @Inject
    RequestHandlerFactory protocolRequestHandlerFactory;

    @Inject
    RequestHandlerUtility requestHandlerUtility;

    @Inject
    private SystemRecorder systemRecorder;

    @EJB
    CertificateManagementLocalService certificateManagementLocalService;

    @Inject
    Logger logger;

    /**
     * This method validates and process the request obtained from CMP. Based on the request type,processing of request will be done by respective handlers.
     * 
     * @param signedCMPServiceRequest
     *            request received from the CMP Service which need to be processed
     */
    @Asynchronous
    public void processRequest(final SignedCMPServiceRequest signedCMPServiceRequest) {
        CMPRequest cMPRequest = null;
        try {
            logger.debug("Validate signedCMPServiceRequest.");
            final Document document = requestHandlerUtility.loadAndValidateRequest(signedCMPServiceRequest.getCmpRequest());
            final X509Certificate requestSignerCertificate = JaxbUtil.getX509CertificateFromDocument(document);
            certificateManagementLocalService.validateCertificateChain(requestSignerCertificate);
            cMPRequest = (CMPRequest) JaxbUtil.getObject(document, CMPRequest.class);
            
            logger.info("Validation is Successful for signedCMPServiceRequest");
            protocolRequestHandlerFactory.getRequestHandler(cMPRequest).handle(cMPRequest);

        } catch (final CertificateNotFoundException certificateNotFoundException) {
            logCustomError("CERTIFICATE NOT FOUND", "PKIMANAGER_CMPSERVICE.CERTIFICATEVALIDATIONFAILED", certificateNotFoundException);

        } catch (final DigitalSignatureValidationException digitalSignatureValidationException) {
            logCustomError("INVALID SIGNATURE ON THE RESPONSE MESSAGE DURING INITIAL ENROLLMENT", "PKIMANAGER_CMP_SECURECOMMUNICATION.DIGITALSIGNATUREVERIFICATION_FAILED", digitalSignatureValidationException);

        } catch (final RevokedCertificateException revokedCertificateException) {
            logCustomError("CHAIN VALIDATION FAILED : CERTIFICATE REVOKED$Dollar99", "PKIMANAGER_CMP_SECURECOMMUNICATION.ISSUERCERTIFICATEREVOKED", revokedCertificateException);

        } catch (final UnmarshalException unmarshalException) {
            logCustomError("ERROR OCCURED WHILE PARSING RESPONSE XML", "PKIMANAGER_CMP_SECURECOMMUNICATION.RESPONSEUNMARSHALLING_FAILED", unmarshalException);

        } catch (final DigitalSigningFailedException digitalSigningFailedException) {
            logCustomError("FAILURE WHILE SIGNING CMPV2 PROTOCOL MESSAGES BY RA DURING INITIAl ENROLLMENT", "PKIMANAGER_CMP_SECURECOMMUNICATION.DIGITALSIGNINGFAILED", digitalSigningFailedException);

        } catch (final CredentialsManagementServiceException credentialsManagementServiceException) {
            logCustomError("INTERNAL ERROR OCCURED IN CREDENTIAL MANAGEMENT", "PKIMANAGER_CMP_SECURECOMMUNICATION.CREDENTIALMANAGERERROR", credentialsManagementServiceException);

        } catch (final MarshalException marshalException) {
            logCustomError("ERROR OCCURED WHILE MARSHALING DATA TO XML", "PKIMANAGER_CMP_SECURECOMMUNICATION.FAILEDTOMARSHAL", marshalException);

        } catch (final CertificateException certificateException) {
            logCustomError("ERROR OCCURED WHILE FETCHING CERTIFICATE FROM CERTIFICATE HOLDER", "PKIMANAGER_CMPSERVICE.CERTIFICATEVALIDATIONFAILED", certificateException);

        } catch (final IOException iOException) {
            logCustomError("ERROR OCCURED WHILE PERFORMING I/O OPERATIONS", "PKIMANAGER_CMPSERVICE.CERTIFICATEVALIDATIONFAILED",iOException);

        } catch (final CertificateServiceException certificateServiceException) {
            logCustomError("ERROR OCCURED WHILE CONVERTING DATA TO MODEL OBJECT ", "PKIMANAGER_CMPSERVICE.DATATOMODELCONVERSIONFAILED", certificateServiceException);

        } catch (final InvalidCAException invalidCAException) {
            logCustomError("ISSUER CERTIFICATE IS REVOKED/EXPIRED ", "PKIMANAGER_CMPSERVICE.CERTIFICATEVALIDATIONFAILED", invalidCAException);
        }

    }

	private void logCustomError(final String errorMessage, final String eventType, final Throwable cause) {
        logger.error(errorMessage);
        logger.debug(errorMessage, cause);
        systemRecorder.recordSecurityEvent("PKIMANAGER_CMP_SECURECOMMUNICATION", "PKIMANAGER_CMP_SECURECOMMUNICATION.CMPServiceRequestProcessor", errorMessage, eventType, ErrorSeverity.CRITICAL,
                "FAILURE");
    }

}
