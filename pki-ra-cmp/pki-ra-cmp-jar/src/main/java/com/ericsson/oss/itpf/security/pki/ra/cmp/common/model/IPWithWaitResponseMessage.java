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
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.PKIBody;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateResponseMessageBuilder;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;

/**
 * This class defines a wrapper over CertRepMessage which is a BouncyCastle defined class for IP with wait response message (extends ResponseMessage). content within PKIBody.
 * <p>
 * Note: Please refer to ResponseMessage class
 * 
 * @author tcsdemi
 *
 */
public class IPWithWaitResponseMessage extends ResponseMessage {

    private static final long serialVersionUID = -3695289339936063782L;
    private CertRepMessage certRepMessage = null;

    public IPWithWaitResponseMessage() {
        /**
         * This is default constructor
         */
    }

    /**
     * This constructor allows to unpack the signedIPResponse which is byte[]
     * 
     * @param signedIPWithWaitResponse
     */
    public IPWithWaitResponseMessage(final byte[] signedIPWithWaitResponse) {
        super(signedIPWithWaitResponse);
    }

    /**
     * This method returns CertRepMessage object which is required in building PKIBody for IP Response
     * 
     * @return
     */
    public CertRepMessage getWaitCertRepMessage() {
        return this.certRepMessage;
    }

    /**
     * This method builds CertRepMessage for IP with wait response for a particular requestID
     * 
     * @param certRequestID
     *            In case RequestMessage contains an array of requests, each request will have an ID(int). So for all requestIDs IP with wait needs to be built.
     */
    public void createWaitCertRepMessage(final int certRequestID) {
        this.certRepMessage = CertificateResponseMessageBuilder.buildWaitingCertRepMessage(certRequestID);
    }

    @Override
    public void createPKIBody(final ASN1Encodable content) {
        responsePKIBody = new PKIBody(Constants.TYPE_INIT_RESPONSE, content);
    }
}
