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
package com.ericsson.oss.itpf.security.pki.ra.cmp.service.ejb;

import java.util.LinkedList;
import java.util.List;

import javax.ejb.Stateless;
import javax.enterprise.inject.Any;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.exception.ProtocolException;
import com.ericsson.oss.itpf.security.pki.common.exception.ValidationException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.CMPService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.asynchresponse.RestSynchResponse;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.CMPTransactionResponseMap;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.BodyValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.HeaderValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.NonceValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.TransactionIdHandlerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.UnsupportedAlgorithmException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request.RequestHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request.RequestHandlerFactory;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request.SenderNameHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.builder.FailureMessageBuilder;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.builder.ResponseBuilder;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.builder.ResponseBuilderFactory;
import com.ericsson.oss.itpf.security.pki.ra.cmp.instrumentation.CMPInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.RequestValidator;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.UseCommonValidator;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.UseValidatorForVC;

/**
 * This class is an implementation of EJB Local interface CMPService
 *
 * @author tcsdemi
 *
 */
@Stateless
public class CMPServiceBean implements CMPService {

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private RequestHandlerFactory requestHandlerFactory;

    @Inject
    private FailureMessageBuilder cMPFailureMessageBuilder;

    @Inject
    private ResponseBuilderFactory responseBuilderFactory;

    @Inject
    @Any
    private Instance<RequestValidator> requestValidatorSource;

    @Inject
    private CMPTransactionResponseMap cMPTransactionResponseMap;

    @Inject
    SenderNameHandler senderNameHandler;

    @Inject
    CMPInstrumentationBean cmpInstrumentationBean;

    private static final String REQUEST_VALIDATION_FAILED_FOR = "REQUEST VALIDATION FAILED FOR";
    private static final String TRANSACTION_ID_ERROR = "TRANSACTION ID IS INVALID OR NULL OR NOT FOUND IN DATABASE";
    private static final String PROTOCOL_ERROR = "PROTOCOL LEVEL ERROR EITHER WHILE PARSING REQUEST, HANDLING/BUILDING RESPONSE";
    private static final String ERROR_BUILDING_RESPONSE = "ERROR BUILDING RESPONSE";
    private static final String XML_SIGNATURE_ERROR = "FAILURE WHILE SIGNING THE CMPV2 PROTOCOL MESSAGES BY RA DURING INITIAL ENROLLMENT.";

    @Override
    public byte[] provide(final RequestMessage pKIRequestMessage) throws ResponseBuilderException {

        String transactionId = null;
        byte[] pKIResponseMessage = null;
        final RequestHandler requestHandler = requestHandlerFactory.getRequestHandler(pKIRequestMessage);
        final ResponseBuilder responseBuilder = responseBuilderFactory.getResponseBuilder(pKIRequestMessage);

        if (responseBuilder == null) {
            pKIResponseMessage = cMPFailureMessageBuilder.build(pKIRequestMessage, "Unknown request type " + pKIRequestMessage.getRequestType());
            return pKIResponseMessage;
        }

        try {

            if (pKIRequestMessage.getRequestType() == Constants.TYPE_INIT_REQ || pKIRequestMessage.getRequestType() == Constants.TYPE_KEY_UPDATE_REQ) {
                cmpInstrumentationBean.setEnrollmentInvocations();
                systemRecorder.recordEvent("CMP_SERVICE.ENROLLMENT_PROCESS_STARTED", EventLevel.COARSE, "CMP_SERVICE.CREDENTIAL_ISSUE_OR_REISSUE", pKIRequestMessage.getSenderName(),
                        pKIRequestMessage.getRequestMessage());
            }
            validateRequest(pKIRequestMessage);
            transactionId = requestHandler.handle(pKIRequestMessage);
            pKIResponseMessage = responseBuilder.build(pKIRequestMessage, transactionId);

            logger.info("Provided CMPv2 Service for Entity: \n Sender:{} \n TransactionID:{} .\n About to send HTTPResponse ",pKIRequestMessage.getSenderName(),pKIRequestMessage.getBase64TransactionID());

        } catch (ValidationException validationException) {
            logErrorMessage(REQUEST_VALIDATION_FAILED_FOR, pKIRequestMessage, validationException);
            pKIResponseMessage = buildCMPErrorMessage(pKIRequestMessage, validationException);

        } catch (ResponseBuilderException responseBuilderException) {
            logErrorMessage(ERROR_BUILDING_RESPONSE, pKIRequestMessage, responseBuilderException);
            pKIResponseMessage = buildCMPErrorMessage(pKIRequestMessage, responseBuilderException);

        } catch (TransactionIdHandlerException transactionIdHandlerException) {
            logErrorMessage(TRANSACTION_ID_ERROR, pKIRequestMessage, transactionIdHandlerException);
            pKIResponseMessage = buildCMPErrorMessage(pKIRequestMessage, transactionIdHandlerException);

        } catch (ProtocolException protocolException) {
            logErrorMessage(PROTOCOL_ERROR, pKIRequestMessage, protocolException);
            pKIResponseMessage = buildCMPErrorMessage(pKIRequestMessage, protocolException);

        } catch (DigitalSigningFailedException digitalSigningFailedException) {
            logErrorMessage(XML_SIGNATURE_ERROR, pKIRequestMessage, digitalSigningFailedException);
            pKIResponseMessage = buildCMPErrorMessage(pKIRequestMessage, digitalSigningFailedException);
        }
        return pKIResponseMessage;

    }

    @Override
    public void provide(final RequestMessage pKIRequestMessage, final RestSynchResponse aysnchResponse) throws ResponseBuilderException {

        String transactionId = null;
        byte[] pKIResponseMessage = null;
        final RequestHandler requestHandler = requestHandlerFactory.getRequestHandler(pKIRequestMessage);

        logger.info("CMPv2 Service Started for Entity: \n {}", pKIRequestMessage.getSenderName());
        try {

            if (pKIRequestMessage.getRequestType() == Constants.TYPE_INIT_REQ || pKIRequestMessage.getRequestType() == Constants.TYPE_KEY_UPDATE_REQ) {
                cmpInstrumentationBean.setEnrollmentInvocations();
                systemRecorder.recordSecurityEvent(pKIRequestMessage.getSenderName(), "CMP_SERVICE", "Issue/Re-Issue credential to network element", "CMP_SERVICE.ENROLLMENT_STARTED",
                        ErrorSeverity.INFORMATIONAL, "STARTED");
            }
            validateRequest(pKIRequestMessage);
            transactionId = requestHandler.handle(pKIRequestMessage);
            cMPTransactionResponseMap.putRestSynchResponse(transactionId, aysnchResponse);

            if (pKIRequestMessage.getRequestType() == Constants.TYPE_CERT_CONF) {
                final ResponseBuilder responseBuilder = responseBuilderFactory.getResponseBuilder(pKIRequestMessage);
                pKIResponseMessage = responseBuilder.build(pKIRequestMessage, transactionId);
                aysnchResponse.send(pKIResponseMessage);
            }

        } catch (ValidationException validationException) {
            logErrorMessage(REQUEST_VALIDATION_FAILED_FOR, pKIRequestMessage, validationException);
            pKIResponseMessage = buildCMPErrorMessage(pKIRequestMessage, validationException);
            aysnchResponse.send(pKIResponseMessage);

        } catch (TransactionIdHandlerException transactionIdHandlerException) {
            logErrorMessage(TRANSACTION_ID_ERROR, pKIRequestMessage, transactionIdHandlerException);
            pKIResponseMessage = buildCMPErrorMessage(pKIRequestMessage, transactionIdHandlerException);
            aysnchResponse.send(pKIResponseMessage);

        } catch (ProtocolException protocolException) {
            logErrorMessage(PROTOCOL_ERROR, pKIRequestMessage, protocolException);
            pKIResponseMessage = buildCMPErrorMessage(pKIRequestMessage, protocolException);
            aysnchResponse.send(pKIResponseMessage);
        } catch (DigitalSigningFailedException digitalSigningFailedException) {
            logErrorMessage(XML_SIGNATURE_ERROR, pKIRequestMessage, digitalSigningFailedException);
            pKIResponseMessage = buildCMPErrorMessage(pKIRequestMessage, digitalSigningFailedException);
            aysnchResponse.send(pKIResponseMessage);
        }
    }

    @Override
    public String getSenderName(final RequestMessage requestMessage) {
        return senderNameHandler.getSenderName(requestMessage);
    }

    private byte[] buildCMPErrorMessage(final RequestMessage pKIRequestMessage, final Throwable cause) throws ResponseBuilderException {
        return cMPFailureMessageBuilder.build(pKIRequestMessage, cause.getMessage());
    }

    private void logErrorMessage(final String errorMessage, final RequestMessage pKIRequestMessage, final Throwable cause) {
        final StringBuilder errorMsg = new StringBuilder();
        errorMsg.append(cause.getClass().getSimpleName());
        errorMsg.append(" - ");
        errorMsg.append(errorMessage);
        errorMsg.append(": {} with TRANSACTION ID: {}, SENDER: {}, SENDER-NONCE: {}, RECEPIENT: {}, RECEPIENT-NONCE: {}, due to :{} ");

        systemRecorder.recordError("CMP_SERVICE.ENROLLMENT_FAILED", ErrorSeverity.ERROR, "CMP_SERVICE.CREDENTIAL_ISSUE_OR_REISSUE", pKIRequestMessage.getSenderName(),
                cause.getMessage() + "[" + pKIRequestMessage.getRequestMessage() + "]");
        final String errMsg = errorMsg.toString();
        logger.error(errMsg, pKIRequestMessage.getRequestMessage(), pKIRequestMessage.getBase64TransactionID(), pKIRequestMessage.getSenderName(),
                pKIRequestMessage.getSenderNonce(), pKIRequestMessage.getRecipientName(), pKIRequestMessage.getRecepientNonce(), cause.getMessage());
        logger.debug("Exception stackTrace : ", cause);
    }

    private void validateRequest(final RequestMessage pKIRequestMessage) throws UnsupportedAlgorithmException, NonceValidationException, HeaderValidationException, BodyValidationException,
            CRLValidationException, CertificateRevokedException, DigitalSignatureValidationException, TransactionIdHandlerException, ProtocolException {
        final RequestHandler requestHandler = requestHandlerFactory.getRequestHandler(pKIRequestMessage);
        final List<RequestValidator> vcValidators = getVcValidators(requestHandler);
        final List<RequestValidator> iakAndVCCommonValidators = getIAKandVCCommonValidators(requestHandler);

        for (final RequestValidator validator : iakAndVCCommonValidators) {
            validator.validate(pKIRequestMessage);
        }

        if (!pKIRequestMessage.isMacBased()) {
            for (final RequestValidator validator : vcValidators) {
                validator.validate(pKIRequestMessage);
            }
        }

    }

    private List<RequestValidator> getVcValidators(final RequestHandler requestHandler) {
        final List<RequestValidator> validators = new LinkedList<>();

        if (requestHandler.getClass().isAnnotationPresent(UseValidatorForVC.class)) {
            final UseValidatorForVC validatorsAnnotation = requestHandler.getClass().getAnnotation(UseValidatorForVC.class);

            for (final Class<? extends RequestValidator> validatorClazz : validatorsAnnotation.value()) {
                validators.add(requestValidatorSource.select(validatorClazz).get());
            }

        }
        return validators;
    }

    private List<RequestValidator> getIAKandVCCommonValidators(final RequestHandler requestHandler) {
        final List<RequestValidator> validators = new LinkedList<>();

        if (requestHandler.getClass().isAnnotationPresent(UseCommonValidator.class)) {
            final UseCommonValidator validatorsAnnotation = requestHandler.getClass().getAnnotation(UseCommonValidator.class);

            for (final Class<? extends RequestValidator> validatorClazz : validatorsAnnotation.value()) {
                validators.add(requestValidatorSource.select(validatorClazz).get());
            }

        }
        return validators;
    }

}
