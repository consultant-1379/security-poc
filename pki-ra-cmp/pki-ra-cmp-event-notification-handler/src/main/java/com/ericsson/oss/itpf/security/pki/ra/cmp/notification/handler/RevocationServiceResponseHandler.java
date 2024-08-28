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

import javax.inject.Inject;

import org.slf4j.Logger;
import org.w3c.dom.Document;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationResponse;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.UnmarshalException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.*;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.util.PKIManagerResponseProcessor;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CMPLocalService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.Constants;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.events.SignedRevocationServiceResponse;

/**
 * This class is responsible for handling revocationResponse obtained from the event bus.
 * 
 * @author tcsramc
 */
public class RevocationServiceResponseHandler {

    @EServiceRef
    CMPLocalService cmpLocalService;

    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    PKIManagerResponseProcessor responseUtility;

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    Logger logger;

    /**
     * This method receives Revocation Response(which will be in the form of XML) from PKI-Manager.Once the response is received it is validated and
     * then extracts Response from it. based on the
     * isvalid parameter in the Response this handler will update the db status to REVOKED/FAILED.
     * 
     * @param signedRevocationServiceResponse
     *            Response which is obtained from pki-manager.
     */
    public void handle(final SignedRevocationServiceResponse signedRevocationServiceResponse) {
        try {
            final Document document = responseUtility.loadAndValidateResponse(signedRevocationServiceResponse.getRevocationServiceResponse());
            final RevocationResponse revocationResponse = JaxbUtil.getObject(document, RevocationResponse.class);

            final boolean revokedStatus = revocationResponse.isRevoked();
            final String transactionID = revocationResponse.getTransactionID();
            final String senderName = revocationResponse.getSubjectName();

            final CMPMessageEntity protocolMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
            final MessageStatus currentDBStatus = protocolMessageEntity.getStatus();
            if (revokedStatus) {
                updateDBforRevokeSuccess(transactionID, protocolMessageEntity, senderName, currentDBStatus);
            } else {
                updateDBforRevokeFail(transactionID, protocolMessageEntity, senderName, currentDBStatus);

            }
        } catch (final DigitalSignatureValidationException digitalSignatureValidationException) {
            logCustomError("INVALID SIGNATURE ON THE RESPONSE MESSAGE", digitalSignatureValidationException,
                    "PKIRACMPService.DIGITALSIGNATUREVERIFICATION_FAILED");

        } catch (final InvalidInitialConfigurationException invalidInitialConfigurationException) {
            logCustomError(ErrorMessages.INVALID_CONFIGURATION_DATA_PRESENT, invalidInitialConfigurationException,
                    "PKIRACMPService.INVALIDINITIALCONFIGURATION");

        } catch (final UnmarshalException unmarshalException) {
            logCustomError("ERROR OCCURED WHILE PARSING RESPONSE XML", unmarshalException, "PKIRACMPService.RESPONSEUNMARSHALLING_FAILED");

        } catch (final CRLValidationException cRLValidationException) {
            logCustomError("ERROR OCCURED WHILE VALIDATING CRL", cRLValidationException, "PKIRACMPSERVICE_SECURECOMMUNICATION.CRLVALIDATION_FAILED");

        } catch (final CertificateRevokedException certificateRevokedException) {
            logCustomError("ERROR OCCURED WHILE VALIDATING CERTIFICATE", certificateRevokedException,
                    "PKIRACMPSERVICE_SECURECOMMUNICATION.CERTIFICATE_REVOKED");

        }
    }

    private void updateDBforRevokeFail(final String transactionID, final CMPMessageEntity protocolMessageEntity, final String senderName,
            final MessageStatus currentDBStatus) {

        if (currentDBStatus.equals(MessageStatus.REVOCATION_IN_PROGRESS_FOR_NEW_CERTIFICATE)) {
            cmpLocalService.updateCMPTransactionStatus(transactionID, senderName, protocolMessageEntity.getResponseMessage(),
                    MessageStatus.TO_BE_REVOKED_NEW, Constants.NO_ERROR_INFO);
        } else if(currentDBStatus.equals(MessageStatus.REVOCATION_IN_PROGRESS_FOR_OLD_CERTIFICATE)){
            cmpLocalService.updateCMPTransactionStatus(transactionID, senderName, protocolMessageEntity.getResponseMessage(),
                    MessageStatus.TO_BE_REVOKED_OLD, Constants.NO_ERROR_INFO);
        }
    }

    private void updateDBforRevokeSuccess(final String transactionID, final CMPMessageEntity protocolMessageEntity, final String senderName,
            final MessageStatus currentDBStatus) {

        if (currentDBStatus.equals(MessageStatus.REVOCATION_IN_PROGRESS_FOR_NEW_CERTIFICATE)) {
            cmpLocalService.updateCMPTransactionStatus(transactionID, senderName, protocolMessageEntity.getResponseMessage(),
                    MessageStatus.REVOKED_NEW_CERTIFICATE, Constants.NO_ERROR_INFO);
        } else {
            cmpLocalService.updateCMPTransactionStatus(transactionID, senderName, protocolMessageEntity.getResponseMessage(),
                    MessageStatus.REVOKED_OLD_CERTIFICATE, Constants.NO_ERROR_INFO);
        }
    }

    private void logCustomError(final String errorMessage, final Throwable cause, final String eventType) {
        systemRecorder.recordSecurityEvent("PKIRACMPSERVICE_SECURECOMMUNICATION",
                "PKIRACMPSERVICE_SECURECOMMUNICATION.RevocationServiceResponseHandler", errorMessage, eventType,
                ErrorSeverity.CRITICAL, "FAILURE");
        logger.error(errorMessage);
        logger.debug("Exception stackTrace: ", cause);
    }

}
