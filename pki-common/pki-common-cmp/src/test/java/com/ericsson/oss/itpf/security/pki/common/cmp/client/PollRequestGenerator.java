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
package com.ericsson.oss.itpf.security.pki.common.cmp.client;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

public class PollRequestGenerator extends AbstractRequestResponse {

    protected PollRequestGenerator(Parameters params) throws Exception {
        super(params);
    }

    public PKIMessage generatePollReq(PKIMessage message) throws Exception {
        int reqType = message.getBody().getType();
        if (reqType != PKIBody.TYPE_INIT_REP && reqType != PKIBody.TYPE_KEY_UPDATE_REP && reqType != PKIBody.TYPE_POLL_REP)
            throw new Exception("NOT SUPPORTED CERT REQUEST TYPE");

        PKIMessage pkiMessage = null;
        PKIHeader pkiHeader = null;
        PKIBody pkiBody = null;
        DERBitString signature = null;

        String recipient = parameters.getRecipientSubjectDN() != null ? parameters.getRecipientSubjectDN() : parameters.getRecipientCA();
        GeneralName recipientGeneralName = new GeneralName(new X500Name(recipient));

        String sender = entityCert.getX509v3PKCert().getSubject().toString();
        GeneralName senderGeneralName = new GeneralName(new X500Name(sender));

        String senderNonce = generateNonce();
        String receipientNonce = convertASN1OctetStringToString(message.getHeader().getSenderNonce());

        String transactionID = convertASN1OctetStringToString(message.getHeader().getTransactionID());
        AlgorithmIdentifier identifier = message.getHeader().getProtectionAlg();
        pkiHeader = createPKIHeader(senderGeneralName, recipientGeneralName, senderNonce, receipientNonce, transactionID, identifier);

        pkiBody = createPKIBodyForPollRequest(reqType, message);

        signature = CMPUtil.signMessage(pkiHeader, pkiBody, parameters.getEntityCredential(), parameters.isValidProtectionBytes());
        pkiMessage = new PKIMessage(pkiHeader, pkiBody, signature, new CMPCertificate[] { entityCert });

        return pkiMessage;
    }

    private PKIBody createPKIBodyForPollRequest(int requestType, PKIMessage message) throws Exception {

        PKIBody pkiBody = null;
        ASN1Integer requestID;

        if (requestType == PKIBody.TYPE_INIT_REP || requestType == PKIBody.TYPE_KEY_UPDATE_REP) {

            final CertRepMessage certRepMessage = CertRepMessage.getInstance(message.getBody().getContent());
            final CertResponse[] certResponses = certRepMessage.getResponse();

            if (certResponses.length != 1) { //As only one IR was sent....
                throw new Exception("NOT 1 CERT RESPONSE " + certResponses.length);
            }

            final CertResponse resp = certResponses[0];
            requestID = resp.getCertReqId();
        } else {
            PollRepContent repContent = (PollRepContent) message.getBody().getContent();
            requestID = repContent.getCertReqId(0);
        }

        DERSequence derSequence = new DERSequence(new DERSequence(requestID));
        PollReqContent reqcontent = PollReqContent.getInstance(derSequence);

        pkiBody = new PKIBody(PKIBody.TYPE_POLL_REQ, reqcontent.toASN1Primitive()); // << TODO Generate PollRequest content

        return pkiBody;
    }

}
