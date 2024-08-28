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
package com.ericsson.oss.itpf.security.pki.common.cmp.model;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.PKIBody;

import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateResponseMessageBuilder;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.exception.ProtocolException;

/**
 * This class is used for generating the response for Initial Response Message.
 * 
 * @author tcsramc
 * 
 */
public class IPResponseMessage extends ResponseMessage {

    private static final long serialVersionUID = 2372882917990432732L;
    private CertRepMessage certRepMessage = null;

    public IPResponseMessage() {
        super();
    }

    /**
     * This constructor sets the fields of response object.
     * 
     * @param cMPResponseByteArray
     *            CMP Response Byte Array from which PKI message need to be extracted
     * @throws ProtocolModelException
     *             is thrown when encoding error occurs
     */
    public IPResponseMessage(final byte[] cMPResponseByteArray) throws ProtocolException {
        super(cMPResponseByteArray);

    }

    /**
     * return CertRepMessage
     * 
     * @return Certificate Response Message
     */
    public CertRepMessage getCertRepMessage() {
        return this.certRepMessage;
    }

    /**
     * @param certRequestID
     *            certificate request ID that need to be set
     * @param userCert
     *            User certificate that need to be set
     * @param trustedCerts
     *            trusted certificates that need to be set
     * @return This method will set CertRepMessage which will be used to createPKIMessage for IP. CertRepMessage will be used in CMPv2IPResponseMessage in createPKIMEssage.
     */
    public void createCertRepMessage(final int certRequestID, final X509Certificate userCert, final List<X509Certificate> trustedCerts) {
        this.certRepMessage = CertificateResponseMessageBuilder.build(certRequestID, userCert, trustedCerts);
        this.encodableContent = certRepMessage;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage# createPKIBody(org.bouncycastle.asn1.ASN1Encodable)
     */
    @Override
    public void createPKIBody(final ASN1Encodable content) {
        responsePKIBody = new PKIBody(Constants.TYPE_INIT_RESPONSE, content);
    }

}
