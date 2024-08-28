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

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.x509.*;

public class CommonResponseGenerator extends AbstractRequestResponse {

    protected CommonResponseGenerator(Parameters params) throws Exception {
        super(params);
    }

    public PKIMessage generateResponse(PKIMessage message, int responseType, boolean isWaiting) throws Exception {

        PKIMessage pkiMessage = null;
        PKIHeader pkiHeader = null;
        PKIBody pkiBody = null;
        CMPCertificate[] extraCerts = null;
        DERBitString signature = null;
        int reqType = message.getBody().getType();

        //start building Header
        GeneralName senderGeneralName = message.getHeader().getRecipient();
        GeneralName recipientGeneralName = message.getHeader().getSender();

        String senderNonce = generateNonce();
        String receipientNonce = convertASN1OctetStringToString(message.getHeader().getSenderNonce());

        String transactionID = convertASN1OctetStringToString(message.getHeader().getTransactionID());
        AlgorithmIdentifier identifier = message.getHeader().getProtectionAlg();

        pkiHeader = createPKIHeader(senderGeneralName, recipientGeneralName, senderNonce, receipientNonce, transactionID, identifier);

        switch (responseType) {
        case PKIBody.TYPE_INIT_REP:
        case PKIBody.TYPE_KEY_UPDATE_REP:
            if (isWaiting) {
                pkiBody = createPKIBodyForIPorKUPWithWait(reqType, message);
            } else {
                pkiBody = createPKIBodyForIPorKUP(reqType, message);
            }
            break;
        case PKIBody.TYPE_POLL_REP:
            pkiBody = createPKIBodyForPollResponse(message);
            break;
        case PKIBody.TYPE_CONFIRM:
            pkiBody = createPKIBodyForPKIConf(message);
        }

        //Generate Protection
        signature = CMPUtil.signMessage(pkiHeader, pkiBody, rAcertDataHolder, parameters.isValidProtectionBytes());

        //Form PKIMessage
        extraCerts = convertToCMPCertArray(rAcertDataHolder.getAdditionalCertificates());
        pkiMessage = new PKIMessage(pkiHeader, pkiBody, signature, extraCerts);

        return pkiMessage;
    }

    private CMPCertificate[] convertToCMPCertArray(final List<Certificate> extraCerts) throws CertificateEncodingException {

        List<CMPCertificate> cMPCertificates = new ArrayList<CMPCertificate>();
        CMPCertificate[] cMPExtraCerts = null;
        for (Certificate c : extraCerts) {
            CMPCertificate cmpCertificate = new CMPCertificate(c);
            cMPCertificates.add(cmpCertificate);
        }
        cMPExtraCerts = cMPCertificates.toArray(new CMPCertificate[cMPCertificates.size()]);

        return cMPExtraCerts;
    }

    private PKIBody createPKIBodyForIPorKUPWithWait(int requestType, PKIMessage message) throws Exception {

        PKIBody pkiBody = null;

        final CertReqMessages certReqMessages = (CertReqMessages) message.getBody().getContent();
        final CertReqMsg[] certReqMsg = certReqMessages.toCertReqMsgArray();
        ASN1Integer requestID = certReqMsg[0].getCertReq().getCertReqId();

        CertResponse[] certResponses = new CertResponse[1];
        CMPCertificate[] caPubs = null;
        PKIStatus pKIStatus = PKIStatus.getInstance(new ASN1Integer(PKIStatus.WAITING));
        PKIStatusInfo pKIStatusInfo = new PKIStatusInfo(pKIStatus);
        CertResponse certResponse = new CertResponse(requestID, pKIStatusInfo);
        certResponses[0] = certResponse;

        CertRepMessage certRepMessage = new CertRepMessage(caPubs, certResponses);

        if (requestType == PKIBody.TYPE_INIT_REQ) {
            pkiBody = new PKIBody(PKIBody.TYPE_INIT_REP, certRepMessage);
        } else {
            pkiBody = new PKIBody(PKIBody.TYPE_KEY_UPDATE_REP, certRepMessage);
        }

        return pkiBody;
    }

    private CertRepMessage createCertRepMessage(PKIMessage message) throws IOException {

        CertRepMessage certRepMessage = null;

        final CertReqMessages certReqMessages = (CertReqMessages) message.getBody().getContent();
        final CertReqMsg[] certReqMsg = certReqMessages.toCertReqMsgArray();
        ASN1Integer requestID = certReqMsg[0].getCertReq().getCertReqId();

        final CertOrEncCert retCert = new CertOrEncCert(new CMPCertificate(org.bouncycastle.asn1.x509.Certificate.getInstance(rAcertDataHolder.getCert().getEncoded())));
        final CertifiedKeyPair certifiedKeyPair = new CertifiedKeyPair(retCert);
        final PKIStatusInfo pKIStatusInfo = new PKIStatusInfo(PKIStatus.getInstance(new ASN1Integer(PKIStatus.GRANTED)));
        final CertResponse certResponse = new CertResponse(requestID, pKIStatusInfo, certifiedKeyPair, new DEROctetString(new byte[] {}));

        certRepMessage = new CertRepMessage(null, new CertResponse[] { certResponse });

        return certRepMessage;
    }

    private PKIBody createPKIBodyForIPorKUP(int requestType, PKIMessage message) throws Exception {
        PKIBody pkiBody = null;
        CertRepMessage certRepMessage = null;

        certRepMessage = createCertRepMessage(message);

        if (requestType == PKIBody.TYPE_INIT_REQ) {
            pkiBody = new PKIBody(PKIBody.TYPE_INIT_REP, certRepMessage);
        } else {
            pkiBody = new PKIBody(PKIBody.TYPE_KEY_UPDATE_REP, certRepMessage);
        }

        return pkiBody;
    }

    private PKIBody createPKIBodyForPollResponse(PKIMessage message) throws Exception {

        PKIBody pkiBody = null;
        final int checkAfter = 60;

        final PollReqContent pollReqContent = (PollReqContent) message.getBody().getContent();
        final ASN1Integer requestID = new ASN1Integer(pollReqContent.getCertReqIds()[0][0].getValue());

        PollRepContent pollRepContent = null;
        pollRepContent = new PollRepContent(requestID, new ASN1Integer(checkAfter));

        pkiBody = new PKIBody(PKIBody.TYPE_POLL_REP, pollRepContent);

        return pkiBody;
    }

    private PKIBody createPKIBodyForPKIConf(PKIMessage message) throws Exception {

        PKIBody pkiBody = null;

        PKIConfirmContent reqcontent = new PKIConfirmContent();

        pkiBody = new PKIBody(PKIBody.TYPE_CONFIRM, reqcontent.toASN1Primitive());

        return pkiBody;
    }

}
