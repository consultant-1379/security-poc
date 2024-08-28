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

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.*;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;
import com.ericsson.oss.itpf.security.pki.common.test.utilities.*;

public class CertificateConfirmationRequest extends AbstractClientRequest implements ClientRequest {

    public CertificateConfirmationRequest(final Parameters params, final PKIMessage forInitialMessage) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, OperatorCreationException,
    NoSuchProviderException, SignatureException, IOException {
        super(params, forInitialMessage);
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

        final CertRepMessage certRepMessage = CertRepMessage.getInstance(initialMessage.getBody().getContent());
        final CertResponse[] certResponses = certRepMessage.getResponse();
        final CertResponse certResponse = certResponses[0];
        final ASN1Integer certRequestId = certResponse.getCertReqId();
        final CertificateConfirmationContentBuilder confirmBuilder = new CertificateConfirmationContentBuilder();
        final CertifiedKeyPair certKeyPair = certResponse.getCertifiedKeyPair();
        final CMPCertificate responseCertificate = certKeyPair.getCertOrEncCert().getCertificate();
        if (!responseCertificate.isX509v3PKCert()) {
            throw new CMPException("NOT X509v3PKCert");
        }
        final X509CertificateHolder certHolder = new X509CertificateHolder(responseCertificate.getX509v3PKCert());
        confirmBuilder.addAcceptedCertificate(certHolder, certRequestId.getValue());
        final CertificateConfirmationContent content = confirmBuilder.build(new JcaDigestCalculatorProviderBuilder().build());
        final PKIBody pkiBody = new PKIBody(PKIBody.TYPE_CERT_CONFIRM, content.toASN1Structure());

        return pkiBody;
    }

    @Override
    public PKIMessage createPKIMessage(final PKIHeader pkiHeader, final PKIBody pkiBody, final DERBitString signature) {
        final PKIMessage certConfRequestMessage = new PKIMessage(pkiHeader, pkiBody, signature, new CMPCertificate[] { entityCert });
        return certConfRequestMessage;
    }

    @Override
    public DERBitString createSignatureString(final PKIHeader pkiHeader, final PKIBody pkiBody) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException,
            IOException {
        final DERBitString signature = SigningUtility.signMessage(pkiHeader, pkiBody, parameters.getEntityCredential(), parameters.isValidProtectionBytes());
        return signature;
    }

}
