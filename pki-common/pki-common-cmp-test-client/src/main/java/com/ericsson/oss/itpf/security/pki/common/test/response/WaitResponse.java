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
package com.ericsson.oss.itpf.security.pki.common.test.response;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.operator.OperatorCreationException;

import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;

public class WaitResponse extends AbstractClientResponse {

    public WaitResponse(final Parameters params) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, NoSuchProviderException, SignatureException,
            IOException {
        super(params);
    }

    @Override
    public PKIBody createPKIBody(final PKIMessage requestMessage) throws IOException {

        final CertReqMessages certReqMessages = (CertReqMessages) requestMessage.getBody().getContent();
        final CertReqMsg[] certReqMsg = certReqMessages.toCertReqMsgArray();
        final ASN1Integer requestID = certReqMsg[0].getCertReq().getCertReqId();
        final CertResponse[] certResponses = new CertResponse[1];
        final CMPCertificate[] caPubs = null;
        final PKIStatus pKIStatus = PKIStatus.getInstance(new ASN1Integer(PKIStatus.WAITING));
        final PKIStatusInfo pKIStatusInfo = new PKIStatusInfo(pKIStatus);
        final CertResponse certResponse = new CertResponse(requestID, pKIStatusInfo);
        certResponses[0] = certResponse;
        final CertRepMessage certRepMessage = new CertRepMessage(caPubs, certResponses);

        PKIBody pkiBody = null;
        if (requestType == PKIBody.TYPE_INIT_REQ) {
            pkiBody = new PKIBody(PKIBody.TYPE_INIT_REP, certRepMessage);
        } else {
            pkiBody = new PKIBody(PKIBody.TYPE_KEY_UPDATE_REP, certRepMessage);
        }
        return pkiBody;
    }

}
