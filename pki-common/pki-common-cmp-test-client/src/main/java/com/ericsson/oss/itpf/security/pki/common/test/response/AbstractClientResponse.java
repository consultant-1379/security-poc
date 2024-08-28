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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.OperatorCreationException;

import com.ericsson.oss.itpf.security.pki.common.test.certificates.CertDataHolder;
import com.ericsson.oss.itpf.security.pki.common.test.certificates.VendorCertificateGenerator;
import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;
import com.ericsson.oss.itpf.security.pki.common.test.utilities.*;

public abstract class AbstractClientResponse implements ClientResponse {

    protected Parameters parameters;
    protected CMPCertificate entityCert;
    protected CertDataHolder rAcertDataHolder;
    protected PKIMessage initialMessage;
    protected int requestType = 0;

    protected AbstractClientResponse(final Parameters params) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, NoSuchProviderException,
            SignatureException, IOException {
        parameters = params;
        if (params.getEntityCredential() == null) {
            final VendorCertificateGenerator vendorGenerator = new VendorCertificateGenerator(params);
            parameters.setEntityCredential(vendorGenerator.getVendorSignedCredentials());
            rAcertDataHolder = CertDataHolder.getRACertDataHolder(this.getClass().getResource(Constants.KEY_STORE_PATH).getPath());
        }
        //rAcertDataHolder = params.getEntityCredential();
        entityCert = new CMPCertificate(parameters.getEntityCredential().getCert());
    }

    @Override
    public PKIHeader createPKIHeader(final PKIMessage message) throws IOException {
        final GeneralName senderGeneralName = message.getHeader().getRecipient();
        final GeneralName recipientGeneralName = message.getHeader().getSender();

        final String senderNonce = RandomIDGenerator.generate();
        final String receipientNonce = RandomIDGenerator.convertASN1OctetStringToString(message.getHeader().getSenderNonce());

        final String transactionID = RandomIDGenerator.convertASN1OctetStringToString(message.getHeader().getTransactionID());
        final AlgorithmIdentifier identifier = message.getHeader().getProtectionAlg();

        final PKIHeader pkiHeader = PKIHeaderUtil.createPKIHeader(parameters, senderGeneralName, recipientGeneralName, senderNonce, receipientNonce, transactionID, identifier);
        return pkiHeader;
    }

    @Override
    public DERBitString createSignatureString(final PKIHeader pkiHeader, final PKIBody pkiBody) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException,
            IOException {
        final DERBitString signature = SigningUtility.signMessage(pkiHeader, pkiBody, rAcertDataHolder, parameters.isValidProtectionBytes());

        return signature;

    }

    @Override
    public PKIMessage createPKIMessage(final PKIHeader pkiHeader, final PKIBody pkiBody, final DERBitString signature) throws CertificateEncodingException {
        final CMPCertificate[] extraCerts = convertToCMPCertArray(rAcertDataHolder.getAdditionalCertificates());
        final PKIMessage pkiMessage = new PKIMessage(pkiHeader, pkiBody, signature, extraCerts);

        return pkiMessage;
    }

    protected CertRepMessage createCertRepMessage(final PKIMessage message) throws IOException {

        final CertReqMessages certReqMessages = (CertReqMessages) message.getBody().getContent();
        final CertReqMsg[] certReqMsg = certReqMessages.toCertReqMsgArray();
        final ASN1Integer requestID = certReqMsg[0].getCertReq().getCertReqId();

        final CertOrEncCert retCert = new CertOrEncCert(new CMPCertificate(org.bouncycastle.asn1.x509.Certificate.getInstance(rAcertDataHolder.getCert().getEncoded())));
        final CertifiedKeyPair certifiedKeyPair = new CertifiedKeyPair(retCert);
        final PKIStatusInfo pKIStatusInfo = new PKIStatusInfo(PKIStatus.getInstance(new ASN1Integer(PKIStatus.GRANTED)));
        final CertResponse certResponse = new CertResponse(requestID, pKIStatusInfo, certifiedKeyPair, new DEROctetString(new byte[] {}));

        final CertRepMessage certRepMessage = new CertRepMessage(null, new CertResponse[] { certResponse });

        return certRepMessage;
    }

    private CMPCertificate[] convertToCMPCertArray(final List<org.bouncycastle.asn1.x509.Certificate> extraCerts) throws CertificateEncodingException {

        final List<CMPCertificate> cMPCertificates = new ArrayList<CMPCertificate>();
        for (org.bouncycastle.asn1.x509.Certificate c : extraCerts) {
            final CMPCertificate cmpCertificate = new org.bouncycastle.asn1.cmp.CMPCertificate(c);
            cMPCertificates.add(cmpCertificate);
        }
        final CMPCertificate[] cMPExtraCerts = cMPCertificates.toArray(new CMPCertificate[cMPCertificates.size()]);

        return cMPExtraCerts;
    }
}