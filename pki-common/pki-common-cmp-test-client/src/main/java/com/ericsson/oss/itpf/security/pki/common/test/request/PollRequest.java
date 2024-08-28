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
package com.ericsson.oss.itpf.security.pki.common.test.request;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.operator.OperatorCreationException;

import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;
import com.ericsson.oss.itpf.security.pki.common.test.utilities.*;

public class PollRequest extends AbstractClientRequest implements ClientRequest {

    public PollRequest(final Parameters params, final PKIMessage message) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, NoSuchProviderException,
    SignatureException, IOException {
        super(params, message);
    }

    @Override
    public PKIHeader createPKIHeader() throws IOException {
        String senderNonce = null;
        if (!parameters.isNullSenderNonce()) {
            senderNonce = RandomIDGenerator.generate();
        }
        final String receipientNonce = RandomIDGenerator.convertASN1OctetStringToString(initialMessage.getHeader().getSenderNonce());
        final String transactionID = RandomIDGenerator.convertASN1OctetStringToString(initialMessage.getHeader().getTransactionID());
        final AlgorithmIdentifier identifier = initialMessage.getHeader().getProtectionAlg();
        final PKIHeader pkiHeader = PKIHeaderUtil.createPKIHeader(parameters, getSenderNameGN(), getRecipientGN(), senderNonce, receipientNonce, transactionID, identifier);

        return pkiHeader;
    }

    @Override
    public PKIBody createPKIBody() throws OperatorCreationException, CMPException, IOException, NoSuchAlgorithmException {
        ASN1Integer requestID;
        if (requestType == PKIBody.TYPE_INIT_REP || requestType == PKIBody.TYPE_KEY_UPDATE_REP) {
            requestID = extractRequestIDFromIPorKUP();
        } else {
            requestID = extractRequestIdFromPollRequest();
        }
        final DERSequence derSequence = new DERSequence(new DERSequence(requestID));
        final PollReqContent reqcontent = PollReqContent.getInstance(derSequence);
        final PKIBody pkiBody = new PKIBody(PKIBody.TYPE_POLL_REQ, reqcontent.toASN1Primitive());

        return pkiBody;
    }

    @Override
    public DERBitString createSignatureString(final PKIHeader pkiHeader, final PKIBody pkiBody) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException,
            IOException {
        final DERBitString signature = SigningUtility.signMessage(pkiHeader, pkiBody, parameters.getEntityCredential(), parameters.isValidProtectionBytes());
        return signature;
    }

    @Override
    public PKIMessage createPKIMessage(final PKIHeader pkiHeader, final PKIBody pkiBody, final DERBitString signature) {
        final PKIMessage pkiMessage = new PKIMessage(pkiHeader, pkiBody, signature, new CMPCertificate[] { entityCert });
        return pkiMessage;
    }

    private ASN1Integer extractRequestIdFromPollRequest() {
        final PollRepContent repContent = (PollRepContent) initialMessage.getBody().getContent();
        final ASN1Integer requestID = repContent.getCertReqId(0);
        return requestID;
    }

    private ASN1Integer extractRequestIDFromIPorKUP() {
        final CertRepMessage certRepMessage = CertRepMessage.getInstance(initialMessage.getBody().getContent());
        final CertResponse[] certResponses = certRepMessage.getResponse();
        final CertResponse certResponse = certResponses[0];
        final ASN1Integer requestID = certResponse.getCertReqId();

        return requestID;
    }

}
