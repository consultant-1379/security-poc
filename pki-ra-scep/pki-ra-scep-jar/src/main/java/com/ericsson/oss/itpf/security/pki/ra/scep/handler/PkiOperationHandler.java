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
package com.ericsson.oss.itpf.security.pki.ra.scep.handler;

import javax.inject.Inject;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.*;
import com.ericsson.oss.itpf.security.pki.common.scep.constants.ErrorResponse;
import com.ericsson.oss.itpf.security.pki.common.scep.constants.ResponseStatus;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepRequest;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepResponse;
import com.ericsson.oss.itpf.security.pki.ra.scep.builder.CertResponseBuilder;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepRequestData;
import com.ericsson.oss.itpf.security.pki.ra.scep.data.Pkcs7ScepResponseData;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.instrumentation.SCEPInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.entity.Pkcs7ScepRequestEntity;
import com.ericsson.oss.itpf.security.pki.ra.scep.processor.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.qualifier.RequestQualifier;

/**
 * This class accepts the SCEP PkiOperation request message and calls the appropriate methods to process that request message and returns the Response message.
 * Implemented instrumentation for the PkiOperation requests for SCEP DDC/DDP information
 *
 * @author xtelsow
 */
@RequestQualifier(Operation.PKIOPERATION)
public class PkiOperationHandler implements RequestHandler {
    @Inject
    private Logger logger;

    @Inject
    private PkiScepResponse pkiScepResponse;
    @Inject
    private PkiOperationReqProcessor pkiOperReqProcessor;
    @Inject
    private GetCertInitProcessor getCertInitProcessor;
    @Inject
    private PkcsRequestProcessor pkcsRequestProcessor;
    @Inject
    private CertResponseBuilder certResponseBuilder;
    @Inject
    private Pkcs7ScepRequestData pkcs7ScepRequestData;
    @Inject
    private Pkcs7ScepResponseData pkcs7ScepResponseData;
    @Inject
    private SystemRecorder systemRecorder;
    @Inject
    SCEPInstrumentationBean scepInstrumentationBean;

    /**
     * This method is used to process the pkiScepRequest based on message type and returns the corresponding pkiScepResponse
     *
     * @param pkiScepRequest
     *            contains the request message from SCEP client which is to be processed.
     * @return PkiScepResponse contains the response message from SCEP service which is to be sent to RestService. PkiScepResponse message contains pkcs7message and contentType as attributes.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * 
     * @throws BadRequestException
     *             is thrown while processing the invalid request message.
     * @throws UnauthorizedException
     *             will be thrown in case of the given PKCSReq message does not have proper entity information.
     * @throws NotImplementedException
     * 
     *             is thrown when the operations for processing for requested message is not implemented.
     */
    @Profiled
    @Override
    public PkiScepResponse handle(final PkiScepRequest pkiScepRequest) throws BadRequestException, UnauthorizedException, NotImplementedException, PkiScepServiceException {

        logger.debug("Handle method in PkiOperationHandler class");
        systemRecorder.recordEvent(
                "PKI_RA_SCEP.PKI_OPERATION_REQUEST_RECEIVED",
                EventLevel.COARSE,
                "SCEP Client",
                "PKIRASCEPService",
                "PKI RA SCEP request has been received from End Entity with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                        + pkcs7ScepRequestData.getEndEntityName());
        byte[] message = pkiScepRequest.getMessage();

        if (StringUtility.isBase64(new String(message))) {
            message = Base64.decode(message);
        }
        pkiScepResponse.setContentType(Constants.PKIOPERATION_CONTENT_TYPE);
        int status = ResponseStatus.PENDING.getStatus();
        FailureInfo failureInfo = FailureInfo.BADALG;
        try {
            pkiOperReqProcessor.processRequest(message, pkiScepRequest.getCaName(), pkcs7ScepRequestData);
        } catch (BadMessageCheckException | UnSupportedAlgException | UnSupportedMsgTypeException e) {
            status = ResponseStatus.FAILURE.getStatus();
            failureInfo = FailureInfo.valueOf(e.getMessage());
        }
        final MessageType messageType = MessageType.getNameByValue(pkcs7ScepRequestData.getMessageType());

        systemRecorder.recordEvent("PKI_RA_SCEP.PKI_OPERATION_REQUEST_RECEIVED_AND_VERIFIED", EventLevel.COARSE, "SCEP Client", "PKIRASCEPService", "Received and verified " + messageType.toString()
                + " request from End Entity with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());

        certResponseBuilder.populateResponseData(pkcs7ScepRequestData, pkiScepRequest.getCaName(), pkcs7ScepResponseData);

        if (ResponseStatus.FAILURE.getStatus() == status) {
            final byte[] response = certResponseBuilder.buildFailureCertResponse(failureInfo);
            pkiScepResponse.setMessage(response);
            systemRecorder.recordEvent("PKI_RA_SCEP.CERT_RESP_BUILD", EventLevel.COARSE, "PKIRASCEPService", "SCEP Enrollement For End Entity",
                    "Enrollement request has been failed for the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            return pkiScepResponse;
        }

        switch (messageType) {
        case PKCSREQ:
        	scepInstrumentationBean.setPkcsRequests();  
            pkcsRequestProcessor.processRequest(pkcs7ScepRequestData, status);
            final byte[] response = certResponseBuilder.buildPendingCertResponse();
            pkiScepResponse.setMessage(response);            
            systemRecorder
                    .recordEvent(
                            "PKI_RA_SCEP.CERT_RESP_BUILD",
                            EventLevel.COARSE,
                            "PKIRASCEPService",
                            "SCEP Enrollement For End Entity",
                            "Certificate enrollment is in pending status for the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                                    + pkcs7ScepRequestData.getEndEntityName());
            break;
        case GETCERTINITIAL:
            final Pkcs7ScepRequestEntity pkcs7ScepRequestEntity = getCertInitProcessor.processRequest(pkcs7ScepRequestData);
            pkiScepResponse = getPkiScepResponse(pkcs7ScepRequestEntity);
            break;
        case GETCERT:
        case GETCRL:
            logger.error("Not implemented message {} received with the transaction id : {} for the End Entity {}" , messageType , pkcs7ScepRequestData.getTransactionId() , pkcs7ScepRequestData.getEndEntityName());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PkiOperationHandler", "The message " + messageType + " is not supported by PKI RA SCEP system with the transaction id :"
                    + pkcs7ScepRequestData.getTransactionId() + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName(), "Unsupported PKI RA SCEP Message", ErrorSeverity.ERROR, "FAILURE");

            throw new NotImplementedMsgTypeException(ErrorMessages.MESSAGE_TYPE_NOT_IMPLEMENTED);
        default:
            logger.error("Unsupported message {} received with the transaction id : {} for the End Entity {}" , messageType , pkcs7ScepRequestData.getTransactionId() , pkcs7ScepRequestData.getEndEntityName());
            systemRecorder.recordSecurityEvent(
                    "PKIRASCEPService",
                    "PkiOperationHandler",
                    "Unsupported message " + messageType + " received with the transaction id :" + pkcs7ScepRequestData.getTransactionId() + " for the End Entity "
                            + pkcs7ScepRequestData.getEndEntityName(), "Unsupported SCEP Message", ErrorSeverity.ERROR, "FAILURE");

            throw new UnSupportedMsgTypeException(ErrorMessages.MESSAGE_TYPE_UNSUPPORTED);
        }
        logger.debug("End of Handle method in PkiOperationHandler class");
        return pkiScepResponse;
    }

    /**
     * getPkiScepResponse calls the respective CertResponseBuilder method based on the status and returns the response
     *
     * @param pkcs7ScepRequestEntity
     *            initial PKCSReq record fetched from database.
     * @return PkiScepResponse contains the response message from SCEP service which is to be sent to RestService.
     * @throws BadRequestException
     *             will be thrown in case of invalid request message.
     * @throws UnauthorizedException
     *             will be thrown in case of when the given PKCSReq message does not have proper entity information.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     */
    private PkiScepResponse getPkiScepResponse(final Pkcs7ScepRequestEntity pkcs7ScepRequestEntity) throws BadRequestException, UnauthorizedException, PkiScepServiceException {

        byte[] response = null;

        final ResponseStatus responseStatus = ResponseStatus.getNameByValue(pkcs7ScepRequestEntity.getStatus());
        switch (responseStatus) {
        case SUCCESS:
            response = certResponseBuilder.buildSuccessCertResponse(pkcs7ScepRequestEntity.getCertificate());
            scepInstrumentationBean.setEnrollmentSuccess();
            systemRecorder.recordEvent("PKI_RA_SCEP.CERT_RESP_BUILD", EventLevel.COARSE, "PKIRASCEPService", "SCEP Enrollement For End Entity",
                    "Certificate enrollment is successful and certificate has been sent to the End Entity with the transaction id :" + pkcs7ScepRequestEntity.getTransactionId()
                            + " for the End Entity " + pkcs7ScepRequestData.getEndEntityName());
            break;
        case PENDING:
            response = certResponseBuilder.buildPendingCertResponse();
            systemRecorder.recordEvent("PKI_RA_SCEP.CERT_RESP_BUILD", EventLevel.COARSE, "PKIRASCEPService", "SCEP Enrollement For End Entity",
                    "Certificate enrollment is in pending status for the End Entity with the transaction id :" + pkcs7ScepRequestEntity.getTransactionId() + " for the End Entity "
                            + pkcs7ScepRequestData.getEndEntityName());
            break;
        case FAILURE:
            mapFailureInfoToExceptions(pkcs7ScepRequestEntity);
            break;
        }
        pkiScepResponse.setMessage(response);

        return pkiScepResponse;
    }

    /**
     * mapFailureInfoToExceptions will map the exceptions generated for a PKCSReq message request during the Certificate generation. This failureMapper will compare the failureInfo of the response
     * with the ErrorResponse and map the corresponding Exceptions.
     *
     * @param pkcs7ScepRequestEntity
     *            initial PKCSReq record fetched from database.
     * @throws BadRequestException
     *             will be thrown in case of InvalidCSRException.
     * @throws UnauthorizedException
     *             will be thrown in case of when the given PKCSReq message does not have proper entity information.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     */

    private void mapFailureInfoToExceptions(final Pkcs7ScepRequestEntity pkcs7ScepRequestEntity) throws BadRequestException, UnauthorizedException, PkiScepServiceException {
        switch (ErrorResponse.valueOf(pkcs7ScepRequestEntity.getFailInfo())) {
        case BAD_REQUEST:
        case INVALID_CSR:
            logger.error("Invalid CSR in the Request message with the transaction id :{}" , pkcs7ScepRequestEntity.getTransactionId());
            systemRecorder.recordError("PKI_RA_SCEP.INVALID_CSR", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollement For End Entity",
                    "Invalid CSR in the enrollment request message with the transaction id :" + pkcs7ScepRequestEntity.getTransactionId());
            throw new BadRequestException(ErrorMessages.INVALID_CSR);
        case UNAUTHORIZED:
            logger.error("Entity is unauthorized for requesting the certificate over SCEP. The SCEP Enrollment transaction id is :{}" , pkcs7ScepRequestEntity.getTransactionId());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PkiOperationHandler", "Entity is unauthorized for requesting the certificate over SCEP. The SCEP Enrollment transaction id is :"
                    + pkcs7ScepRequestEntity.getTransactionId(), "Authorization", ErrorSeverity.ERROR, "FAILURE");
            throw new UnauthorizedException(ErrorMessages.UNAUTHORIZED);
        case CERTIFICATE_EXISTS:
            logger.error("Certificate already exists in the request with the transaction id :{}" , pkcs7ScepRequestEntity.getTransactionId());
            systemRecorder.recordError("PKI_RA_SCEP.CERTIFICATE_ALREADY_EXISTS_ERROR", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollement For End Entity",
                    "Certificate already exists for the requested End Entity  with the transaction id :" + pkcs7ScepRequestEntity.getTransactionId());
            throw new PkiScepServiceException(ErrorMessages.CERTIFICATE_EXISTS);
        case ENTITY_NOT_FOUND:
            logger.error("Requested Entity is not found in the data base in PKCS7 Request with the transaction id :{}" , pkcs7ScepRequestEntity.getTransactionId());
            systemRecorder.recordError("PKI_RA_SCEP.ENTITY_NOT_FOUND", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollement For End Entity",
                    "Entity is not found in the PKI RA SCEP system for the certificate request with the transaction id :" + pkcs7ScepRequestEntity.getTransactionId());
            throw new UnauthorizedException(ErrorMessages.ENTITY_NOT_FOUND);
        case INVALID_ENTITY:
            logger.error("Invalid entity found in the request message with the transaction id :{}" , pkcs7ScepRequestEntity.getTransactionId());
            systemRecorder.recordError("PKI_RA_SCEP.INVALID_ENTITY", ErrorSeverity.ERROR, "SCEP Client", "SCEP Enrollement For End Entity",
                    "Invalid entity found in the request message with the transaction id :" + pkcs7ScepRequestEntity.getTransactionId());
            throw new UnauthorizedException(ErrorMessages.INVALID_ENTITY);
        case INVALID_OTP:
            logger.error("Invalid OTP found in the request message with the transaction id :{}" , pkcs7ScepRequestEntity.getTransactionId());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PkiOperationHandler",
                    "Invalid OTP found in the enrollment request with the transaction id :" + pkcs7ScepRequestEntity.getTransactionId(), "Authorization", ErrorSeverity.ERROR, "FAILURE");
            throw new UnauthorizedException(ErrorMessages.INVALID_OTP);
        case OTP_EXPIRED:
            logger.error("OTP expired for the requested entity in PKCS7 request message with the transaction id :{}" , pkcs7ScepRequestEntity.getTransactionId());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PkiOperationHandler", "OTP expired for the requested entity in PKCS7 for the certificate request with the transaction id :"
                    + pkcs7ScepRequestEntity.getTransactionId(), "Authorization", ErrorSeverity.ERROR, "FAILURE");
            throw new UnauthorizedException(ErrorMessages.OTP_EXPIRED);
        case INTERNAL_ERROR:
            logger.error("Failure during generation of certificate for the enrollment request with the transaction id :{}" , pkcs7ScepRequestEntity.getTransactionId());
            systemRecorder.recordError("PKI_RA_SCEP.INTERNAL_ERROR", ErrorSeverity.ERROR, "PKIRASCEPService", "SCEP Enrollement For End Entity",
                    "Failure during generation of certificate for the request with the transaction id :" + pkcs7ScepRequestEntity.getTransactionId());

            throw new PkiScepServiceException(ErrorMessages.REQUEST_PROCESS_FAILURE);
        case OTP_NOT_FOUND:
            logger.error("OTP is not found in the CSR in PKCS7 request message with the transaction id :{}" , pkcs7ScepRequestEntity.getTransactionId());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "PkiOperationHandler",
                    "OTP is not found in the PKCS7 request with the transaction id :" + pkcs7ScepRequestEntity.getTransactionId(), "Authorization", ErrorSeverity.ERROR, "FAILURE");
            throw new BadRequestException(ErrorMessages.OTP_NOT_FOUND);
        }
    }
}
