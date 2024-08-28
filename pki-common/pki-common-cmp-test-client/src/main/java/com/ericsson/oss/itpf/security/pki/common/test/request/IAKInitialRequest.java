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

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.operator.OperatorCreationException;

import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;
import com.ericsson.oss.itpf.security.pki.common.test.utilities.*;

public class IAKInitialRequest extends AbstractClientRequest implements ClientRequest {

    public IAKInitialRequest(final Parameters params) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, NoSuchProviderException,
    SignatureException, IOException {
        super(params);
    }

    @Override
    public PKIHeader createPKIHeader() {
        String senderNonce = null;
        String transactionID = null;
        if (!parameters.isNullSenderNonce()) {
            senderNonce = RandomIDGenerator.generate();
        }
        if (parameters.isSendTransactionID()) {
            if (parameters.getTransactionID() == null) {
                transactionID = RandomIDGenerator.generate();
            }
        }
        final AlgorithmIdentifier validAlgorithmIdentifier = SigningUtility.getAlgorithmIdentifierForIAK();
        final PKIHeader pkiHeader = PKIHeaderUtil.createPKIHeader(parameters, getSenderNameGN(), getRecipientGN(), senderNonce, null, transactionID, validAlgorithmIdentifier);
        return pkiHeader;
    }

    @Override
    public PKIBody createPKIBody() throws OperatorCreationException, CMPException, IOException, NoSuchAlgorithmException {
        final OptionalValidity optValidity = CertificateRequestMessageUtility.buildOptionalValidity(parameters);
        final Extensions extensions = CertificateRequestMessageUtility.buildCertificateExtensions();
        final SubjectPublicKeyInfo publicKeyInfo = CertificateRequestMessageUtility.retrievePublicKeyInfo(parameters);
        final CertTemplate certTemplate = buildCertTemplate(optValidity, extensions, publicKeyInfo);
        final CertReqMsg message = CertificateRequestMessageUtility.formCertificateRequestMsg(certTemplate, parameters);
        final CertReqMessages messages = new CertReqMessages(message);
        PKIBody pkiBody = null;
        if (parameters.isValidRequestType()) {
            pkiBody = new PKIBody(PKIBody.TYPE_INIT_REQ, messages);
        } else {
            pkiBody = new PKIBody(PKIBody.TYPE_CROSS_CERT_REQ, messages);
        }

        return pkiBody;
    }

    @Override
    public PKIMessage createPKIMessage(final PKIHeader pkiHeader, final PKIBody pkiBody, final DERBitString signature) {
        final PKIMessage pKIMessage = new PKIMessage(pkiHeader, pkiBody, signature, new CMPCertificate[] { entityCert });
        return pKIMessage;
    }

    @Override
    public DERBitString createSignatureString(final PKIHeader pkiHeader, final PKIBody pkiBody) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException,
            IOException {
        String iakVakue = "admin";
        if (!parameters.isValidIAK()) {
            iakVakue = "admin1";
        }
        DERBitString signature = SigningUtility.signMessageUsingIAK(pkiHeader, pkiBody, iakVakue);
        if (parameters.getMode() == WorkingMode.WRONG_DIGITAL_SIGN_IR) {
            signature = new DERBitString("THIS IS REALLY NOT A SIGNATURE".getBytes());
        }

        return signature;
    }

}
