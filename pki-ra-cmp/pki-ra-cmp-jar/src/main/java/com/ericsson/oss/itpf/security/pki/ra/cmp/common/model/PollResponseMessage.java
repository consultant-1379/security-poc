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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.model;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PollRepContent;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;

/**
 * This class is PollResponseMessage which extends ResponseMessage. PollResponseMessage provides a wrapper over PollRepContent which is a 3pp BouncyCastle class.
 * 
 * @author tcsdemi
 *
 */
public class PollResponseMessage extends ResponseMessage {

    private static final long serialVersionUID = -3695289339936063782L;
    private PollRepContent pollRepContent = null;

    public PollResponseMessage() {
        /**
         * This is default constructor
         */
    }

    /**
     * This constructor allows to unpack the signedPollResponseMessage which is byte[]
     * 
     * @param signedPollResponseMessage
     */
    public PollResponseMessage(final byte[] signedPollResponseMessage) {
        super(signedPollResponseMessage);
    }

    /**
     * Retrieves pollRepContent from PollResponseMessage object
     * 
     * @return pollRepContent-This is used to create poll response content in pkiBody
     */
    public PollRepContent getPollRepContent() {
        return this.pollRepContent;
    }

    /**
     * This method create polling response content based on RequestID and polling time
     * 
     * @param certRequestId
     *            In case RequestMessage consists of multiple CMP Requests, then for each request there will be a requestID for which a polling response needs to be build
     * @param checkAfter
     *            This is time in seconds which conveys that how much time node has to wait till it can send next Polling request.
     */
    public void createPollRepContent(final int certRequestId, final int checkAfter) {
        pollRepContent = new PollRepContent(new ASN1Integer(certRequestId), new ASN1Integer(checkAfter));

    }

    @Override
    public void createPKIBody(final ASN1Encodable content) {
        responsePKIBody = new PKIBody(Constants.TYPE_POLL_RESPONSE, content);
    }

}
