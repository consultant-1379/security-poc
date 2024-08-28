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
package com.ericsson.oss.itpf.security.pki.common.cmp.util;

import java.io.IOException;

import javax.naming.InvalidNameException;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.CMPRequestType;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.UnsupportedRequestTypeException;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;

/**
 * This contains PKIMessage functionalities
 * 
 * @author tcsramc
 *
 */
/**
 * @author tcslant
 * 
 */
public class PKIMessageUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateUtility.class);
    private PKIMessageUtil() {

    }

    /**
     * Based on the requestType we will extract and return requestId from the CertRepMessage.
     * 
     * @param requestType
     *            Request Type of the PKIMessage
     * @param pKIMessage
     *            PKIMessage from which certificate Request ID is generated
     * @return certificate Request ID
     */
    public static int getRequestId(final PKIMessage pKIMessage) {
        int certReqId = 0;
        final int requestType = pKIMessage.getBody().getType();
        switch (requestType) {
        case Constants.TYPE_INIT_REQ:
        case Constants.TYPE_KEY_UPDATE_REQ: {
            final CertReqMessages certReqMessages = (CertReqMessages) pKIMessage.getBody().getContent();
            final CertReqMsg[] certReqMsg = certReqMessages.toCertReqMsgArray();
            final ASN1Integer requestID = certReqMsg[0].getCertReq().getCertReqId();
            certReqId = requestID.getValue().intValue();
            break;
        }
        case Constants.TYPE_POLL_REQ: {
            final PollReqContent pollReqContent = (PollReqContent) pKIMessage.getBody().getContent();
            final ASN1Integer requestID = new ASN1Integer(pollReqContent.getCertReqIds()[0][0].getValue());
            certReqId = requestID.getValue().intValue();
            break;
        }
        default:
            break;

        }
        LOGGER.debug("Extracted Request ID [{}] from certificate response message", certReqId);
        return certReqId;
    }

    /**
     * This method converts requestType into respective Message(in stringFormat).
     * 
     * @param requestType
     *            Request Type of the PKIMessage
     * @return String format of the RequestType
     */
    public static String convertRequestTypeToString(final int requestType) {
        String requestMessage = CMPRequestType.INVALID_REQUEST.toString();

        switch (requestType) {
        case PKIBody.TYPE_INIT_REQ:
            requestMessage = CMPRequestType.INITIALIZATION_REQUEST.toString();
            break;

        case PKIBody.TYPE_KEY_UPDATE_REQ:
            requestMessage = CMPRequestType.KEY_UPDATE_REQUEST.toString();
            break;

        case PKIBody.TYPE_CERT_CONFIRM:
            requestMessage = CMPRequestType.CERTIFICATE_CONFIRMATION.toString();
            break;

        case PKIBody.TYPE_POLL_REQ:
            requestMessage = CMPRequestType.POLL_REQUEST.toString();
            break;

        default:
            break;
        }
        return requestMessage;
    }

    /**
     * Fetches and returns Subject from the PKIMessage.
     * 
     * @param message
     *            PKIMessage from which CN is extracted
     * @return Subject CN extracted from the PKIMessage
     * @throws InvalidNameException
     *             is thrown if syntax violation occurs
     * @throws UnsupportedRequestTypeException
     *             is thrown if unsupported request comes
     */
    public static String getSubjectCNfromPKIMessage(final PKIMessage message) throws InvalidNameException, UnsupportedRequestTypeException {
        final String entityDN = getSubjectDNfromPKIMessage(message);
        return StringUtility.getCNfromDN(entityDN);
    }

    /**
     * Fetches and returns Subject DN from the PKIMessage.
     * 
     * @param message
     *            PKIMessage from which DN is extracted
     * @return Subject DN extracted from the PKIMessage
     * @throws InvalidNameException
     *             is thrown if syntax violation occurs
     * @throws UnsupportedRequestTypeException
     *             is thrown if unsupported request comes
     */
    public static String getSubjectDNfromPKIMessage(final PKIMessage message) throws InvalidNameException, UnsupportedRequestTypeException {
        final CertReqMsg certReqMsg = getCertReqMsg(message);
        final CertTemplate certTemplate = certReqMsg.getCertReq().getCertTemplate();
        return certTemplate.getSubject().toString();
    }

    /**
     * This method is used get the certificate request message from the PKI message.
     * 
     * @param message
     *            PKIMessage from which CN is extracted
     * @return Certificate request message
     * @throws UnsupportedRequestTypeException
     *             is thrown if unsupported request comes
     */
    public static CertReqMsg getCertReqMsg(final PKIMessage message) throws UnsupportedRequestTypeException {
        LOGGER.debug("Getting certificate request message from the PKI message");
        final int requestType = message.getBody().getType();
        if (requestType != PKIBody.TYPE_INIT_REQ && requestType != PKIBody.TYPE_KEY_UPDATE_REQ) {
            LOGGER.error(ErrorMessages.UNKNOWN_MESSAGE_TYPE);
            throw new UnsupportedRequestTypeException(ErrorMessages.UNKNOWN_MESSAGE_TYPE);
        }
        CertReqMsg certReqMsg = null;
        final PKIBody body = message.getBody();
        final CertReqMessages certReqMessages = (CertReqMessages) body.getContent();
        certReqMsg = certReqMessages.toCertReqMsgArray()[0];
        return certReqMsg;

    }

    /**
     * This method is used to convert ByteArray to PKImessage.
     * 
     * @param inputByteArray
     *            which we need to convert to PKIMessage.
     * @return pkimessage.
     * @throws MessageParsingException
     *             is thrown if any parsing error occurs.
     * @throws IOException
     *             is thrown if any I/O error occurs.
     */
    public static PKIMessage pKIMessageFromByteArray(final byte[] inputByteArray) throws MessageParsingException, IOException {
        final ASN1InputStream inputStream = new ASN1InputStream(inputByteArray);
        PKIMessage pKIMessage = null;
        try {
            final ASN1Primitive rawMessage = inputStream.readObject();
            pKIMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(rawMessage));
        } catch (IOException ioException) {
            LOGGER.error(ErrorMessages.IO_EXCEPTION);
            throw new MessageParsingException(ErrorMessages.IO_EXCEPTION, ioException);
        } finally {
            inputStream.close();
        }
        return pKIMessage;
    }

    /**
     * This method is used to delete UserCertificate from the ExtraCertificates.(in cases required to form PKIMessage).
     * 
     * @param pKIMessage
     *            from which Extracerts needs to be fetched and need to delete user certificate.
     * @return pki message without usercertificate.
     * @throws IOException
     *             is thrown if any I/O Error Occurs.
     */
    public static PKIMessage deleteUserCertificateFromExtraCerts(final PKIMessage pKIMessage) throws IOException {
        final PKIMessage pKIMessageWithOutExtraCertificates = new PKIMessage(pKIMessage.getHeader(), pKIMessage.getBody());
        return pKIMessageWithOutExtraCertificates;
    }
}
