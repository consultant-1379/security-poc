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
import org.bouncycastle.operator.OperatorCreationException;

import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;

public class PollResponse extends AbstractClientResponse {

    public PollResponse(final Parameters params) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, NoSuchProviderException, SignatureException,
            IOException {
        super(params);
    }

    @Override
    public PKIBody createPKIBody(final PKIMessage requestMessage) throws IOException {

        final int checkAfter = 60;
        final PollReqContent pollReqContent = (PollReqContent) requestMessage.getBody().getContent();
        final ASN1Integer requestID = new ASN1Integer(pollReqContent.getCertReqIds()[0][0].getValue());
        final PollRepContent pollRepContent = new PollRepContent(requestID, new ASN1Integer(checkAfter));
        final PKIBody pkiBody = new PKIBody(PKIBody.TYPE_POLL_REP, pollRepContent);

        return pkiBody;
    }

}
