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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.common.builders;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.scep.constants.ErrorResponse;
import com.ericsson.oss.itpf.security.pki.common.scep.model.ScepResponse;
import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.AttachedSignatureXMLBuilder;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl.CredentialsManager;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepResponseMessage;

/**
 * 
 * 
 * The ScepResponseBuilder builds the SignedScepResponseMessage and sends the response to the SignedScepResponseMessageDispatcher.
 * 
 * 
 * If the certificate generation is successful then the SCEPResponseMessage will contain attached digital signature XML as a byte array, which contains the transactionId,Status as SUCCESS ,Certificate
 * in byte stream , failureInfo as null.
 * 
 * If the certificate generation is failed due to an exception the scepResponseMessage will be dispatched with transactionId , Status as FAILED, certificate as null and the appropriate failure Info.
 * 
 * @author xananer
 * 
 */

public class ScepResponseBuilder {

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private CredentialsManager credentialsManager;

    /**
     * buildScepResponse is used to build the SignedScepResponseMessage and dispatch that message to SignedScepResponseMessageDispatcher for sending over the channel.
     * 
     * @param transactionId
     *            is a string attribute which is the transaction id of the PKCSReq message sent for the certificate generation.
     * @param status
     *            is a string attribute which will determine the status of the Certificate generation process.
     * @param failureInfo
     *            is the String attribute which will be present with an appropriate failure reason if the Certificate is not generated.
     * @param certificate
     *            is the generated Certificate of type X509Certificate and it will be set to the Certificate field of the ScepResponseMessage which will be sent over the ScepResponseChannel.
     * 
     * @return SignedScepResponseMessage is the response message to be returned for given PKCS request message.
     */

    public SignedScepResponseMessage buildScepResponse(final String transactionId, final int status, String failureInfo, final X509Certificate certificate) throws DigitalSigningFailedException {
        logger.info("Entering buildScepResponse method of ScepResponseBuilder");
        byte[] responseCertificate = null;
        try {
            if (certificate != null) {
                responseCertificate = certificate.getEncoded();
            }
        } catch (final CertificateEncodingException e) {

            failureInfo = ErrorResponse.CERTIFICATE_ENCODING_ERROR.getValue();
            logger.debug(ErrorMessages.CERTIFICATE_ENCODING_FAILED, e);
        }
        final ScepResponse scepResponse = prepareScepResponseXMLData(transactionId, status, failureInfo, responseCertificate);
        byte[] scepResponseByteArray = null;
        try {
            scepResponseByteArray = buildSignedScepResponseMessage(scepResponse);
        } catch (final DigitalSigningFailedException | CredentialsManagementServiceException e) {
            logger.error(ErrorMessages.FAIL_TO_SIGN_SCEP_RESPONSE_MESSAGE, " with Tansaction Id {}", transactionId);
            throw new DigitalSigningFailedException(ErrorMessages.FAIL_TO_SIGN_SCEP_RESPONSE_MESSAGE + " with Tansaction Id " + transactionId, e);
        }
        final SignedScepResponseMessage signedScepResponseMessage = new SignedScepResponseMessage();
        signedScepResponseMessage.setScepResponse(scepResponseByteArray);
        logger.info("End of buildScepResponse method of ScepResponseBuilder");
        systemRecorder.recordEvent("PKI_MANAGER_SCEP.SCEP_RESPONSE_BUILD", EventLevel.COARSE, "ScepResponseBuilder", "SCEP Service",
                "Scep Response Message biult and dispatched message to ScepResponseMessageDispatcher for Transaction Id :" + transactionId);
        return signedScepResponseMessage;
    }

    private ScepResponse prepareScepResponseXMLData(final String transactionId, final int status, final String failureInfo, final byte[] responseCertificate) {
        final ScepResponse scepResponse = new ScepResponse();
        scepResponse.setTransactionId(transactionId);
        scepResponse.setStatus(status);
        scepResponse.setFailureInfo(failureInfo);
        scepResponse.setCertificate(responseCertificate);
        return scepResponse;
    }

    /**
     * This method will sign the ScepResponse and return the byte array of scep response.
     * 
     * @return byte[] scepRespone to be to set to ScepResponseMessage.
     */
    private byte[] buildSignedScepResponseMessage(final ScepResponse scepResponse) throws DigitalSigningFailedException, CredentialsManagementServiceException {
        X509Certificate signerCertificate = null;
        byte[] scepResponseByteArray = null;
        signerCertificate = credentialsManager.getSignerCertificate();
        final PrivateKey signerPrivateKey = credentialsManager.getSignerPrivateKey();
        scepResponseByteArray = AttachedSignatureXMLBuilder.build(signerCertificate, signerPrivateKey, scepResponse);
        return scepResponseByteArray;
    }
}
