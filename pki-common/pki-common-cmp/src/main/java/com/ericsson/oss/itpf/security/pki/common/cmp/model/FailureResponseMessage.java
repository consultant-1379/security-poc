/*------------------------------------------------------------------------------
 *******************************************************************************
a * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.common.cmp.model;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cmp.*;

import com.ericsson.oss.itpf.security.pki.common.exception.ProtocolException;

/**
 * This class is used for getting and setting the error information related to Failure Response Message
 * 
 * @author tcschdy
 * 
 */
public class FailureResponseMessage extends ResponseMessage {

    private static final long serialVersionUID = 314106197610220365L;
    private String errorMessage = null;
    private ErrorMsgContent errorMsgContent = null;

    /**
     * Constructor calls the super implementation which sets all parameters for ResponseMessage.
     * 
     * @param pKIRequestMessage
     *            PKI Request message
     * @param errorMessageFromManager
     *            Error message in the exception received from the pki manager
     * @throws IOException
     *             is thrown when any I/O exception occurs during encoding
     * @throws ProtocolModelException
     *             is thrown when encoding error occurs
     */
    public FailureResponseMessage(final RequestMessage pKIRequestMessage, final String errorMessageFromManager) throws IOException, ProtocolException {
        super(pKIRequestMessage.getPKIMessage().getEncoded());
        errorMessage = errorMessageFromManager;
    }

    /**
     * Returns Error ResponseMessage
     * 
     * @param errorBytesSentFromManager
     *            The error bytes sent from the manager
     * @throws ProtocolModelException
     *             is thrown when error occurs during encoding
     */
    public FailureResponseMessage(final byte[] errorBytesSentFromManager) throws ProtocolException {
        super(errorBytesSentFromManager);
    }

    /**
     * Returns ResponseMessage
     * 
     * @param errorMessageFromManager
     *            Error message in the exception received from the pki manager
     */
    public FailureResponseMessage(final String errorMessageFromManager) {
        errorMessage = errorMessageFromManager;
    }

    /**
     * This method returns errorMessage
     * 
     * @return error message
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * This method sets the error message.
     * 
     * @param errorMessage
     *            error message that need to be set
     */
    public void setErrorMessage(final String errorMessage) {
        this.errorMessage = errorMessage;
    }

    /**
     * This method is used to form errorInfo by mapping errorMessage with the Exceptions.
     */
    public void createErrorMsgContent() {
        PKIStatusInfo errorStatusInfo;
        errorStatusInfo = PKIStatusInfoMapper.map(errorMessage);
        this.errorMsgContent = new ErrorMsgContent(errorStatusInfo);
    }

    /**
     * returns ErrorMsgContent
     * 
     * @return content of the error message
     */
    public ErrorMsgContent getErrorMsgContent() {
        return errorMsgContent;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage# createPKIBody(org.bouncycastle.asn1.ASN1Encodable)
     */
    @Override
    public void createPKIBody(final ASN1Encodable content) {
        responsePKIBody = new PKIBody(23, content);
    }

}
