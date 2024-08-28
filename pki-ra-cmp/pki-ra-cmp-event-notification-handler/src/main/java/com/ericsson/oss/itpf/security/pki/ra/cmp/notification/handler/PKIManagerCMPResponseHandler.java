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

package com.ericsson.oss.itpf.security.pki.ra.cmp.notification.handler;


import javax.ejb.Asynchronous;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;
import org.w3c.dom.Document;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.DigitalSignatureValidator;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.UnmarshalException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.InitialConfiguration;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.ResponseHandlerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.PKIManagerResponseProcessor;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.handler.ResponseHandlerFactory;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CMPLocalService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceResponse;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;

/**
 * This class deals with response from PKI-Manager, <code>ProtocolServiceResponseEventListener</code> will delegate any response from PKI-Manager to
 * this class.
 *
 * @author tcsdemi
 */
public class PKIManagerCMPResponseHandler {

    @Inject
    ResponseHandlerFactory responseHandlerFactory;

    @Inject
    Logger logger;

    @Inject
    InitialConfiguration initialConfiguration;

    @Inject
    DigitalSignatureValidator digitalSignatureValidator;

    @Inject
    PKIManagerResponseProcessor responseUtility;

    @EServiceRef
    CMPLocalService cmpLocalService;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method handles responses from PKI-Manager. ProtocolServiceResponseEventListener delegates asynchronously all modeled events to this
     * method.
     *
     * @param signedCMPServiceResponse
     *            It is a modeled event which will be received over the modeled event bus which will contain responseType/ResponseBytes/TransactionId
     */
    @Asynchronous
    public void handle(final SignedCMPServiceResponse signedCMPServiceResponse) {
        CMPResponse cMPResponse = new CMPResponse();

        try {

            final Document document = responseUtility.loadAndValidateResponse(signedCMPServiceResponse.getCmpResponse());
            cMPResponse = JaxbUtil.getObject(document, CMPResponse.class);

            logger.info(
                    "Received CMPResponse from PKI-Manager with the following details : transaction id [{}], entity name [{}], response type [{}], error info [{}] and sync response [{}]",
                    cMPResponse.getTransactionID(), cMPResponse.getEntityName(), cMPResponse.getResponseType(), cMPResponse.getErrorInfo(),
                    cMPResponse.getSyncResponse());

            responseHandlerFactory.getResponseHandler(cMPResponse).handle(cMPResponse);
        } catch (final ResponseHandlerException responseException) {
            logCustomError("UNKNOWN REQUEST TYPE FROM PKI-MANAGER, UNKNOWN ERROR WHILE PREPARING RESPONSE IN MANAGER", responseException,
                    "PKIRACMPService.RESPONSEHANDLEREXCEPTION");
            cmpLocalService.updateCMPTransactionStatus(cMPResponse.getTransactionID(), cMPResponse.getEntityName(), cMPResponse.getCmpResponse(),
                    MessageStatus.FAILED, cMPResponse.getErrorInfo());

        } catch (final ResponseSignerException responseSignerException) {
            logCustomError("ERROR WHILE SIGNING MESSAGE FROM PKI-MANAGER.", responseSignerException, "PKIRACMPSERVICE_RESPONSESIGNINGFAILED");
            cmpLocalService.updateCMPTransactionStatus(cMPResponse.getTransactionID(), cMPResponse.getEntityName(), cMPResponse.getCmpResponse(),
                    MessageStatus.FAILED, cMPResponse.getErrorInfo());

        } catch (final DigitalSignatureValidationException digitalSignatureValidationException) {
            logCustomError("INVALID SIGNATURE ON THE RESPONSE MESSAGE DURING INITIAL ENROLLMENT", digitalSignatureValidationException,
                    "PKIRACMPSERVICE_SECURECOMMUNICATION.DIGITALSIGNATUREVERIFICATION_FAILED");

        } catch (final InvalidInitialConfigurationException invalidInitialConfigurationException) {
            logCustomError("INITIAL CONFIGURATION ISSUE / INVALID CERTIFICATE OF CMPv2 RA/ISSUER ARISE DURING INITIAL ENROLLMENT",
                    invalidInitialConfigurationException,
                    "PKIRACMPSERVICE_SECURECOMMUNICATION.INVALIDINITIALCONFIGURATION");

        } catch (final UnmarshalException unmarshalException) {
            logCustomError("ERROR OCCURED WHILE PARSING RESPONSE XML", unmarshalException,
                    "PKIRACMPSERVICE_SECURECOMMUNICATION.RESPONSEUNMARSHALLING_FAILED");

        } catch (final CRLValidationException cRLValidationException) {
            logCustomError("ERROR OCCURED WHILE VALIDATING CRL", cRLValidationException, "PKIRACMPSERVICE_SECURECOMMUNICATION.CRLVALIDATION_FAILED");

        } catch (final CertificateRevokedException certificateRevokedException) {
            logCustomError("ERROR OCCURED WHILE VALIDATING CERTIFICATE", certificateRevokedException,
                    "PKIRACMPSERVICE_SECURECOMMUNICATION.CERTIFICATE_REVOKED");

        } catch (final PersistenceException persistenceException) {
            logCustomError("ERROR OCCURED WHILE UPDATING THE STATUS", persistenceException,
                    "PKIRACMPSERVICE_SECURECOMMUNICATION.STATUSUPDATE_FAILED");
        }
    }

    private void logCustomError(final String errorMessage, final Throwable cause, final String eventType) {
        systemRecorder.recordSecurityEvent("PKIRACMPSERVICE_SECURECOMMUNICATION", "PKIRACMPSERVICE_SECURECOMMUNICATION.PKIManagerCMPResponseHandler",
                errorMessage, eventType, ErrorSeverity.CRITICAL,
                "FAILURE");
        logger.error(errorMessage);
        logger.debug("Exception stackTrace: ", cause);
    }
}
