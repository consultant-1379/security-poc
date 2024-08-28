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

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class InitialOrKeyUpdateRequestGenerator extends AbstractRequestResponse {

    protected InitialOrKeyUpdateRequestGenerator(Parameters params) throws Exception {
        super(params);

    }

    public PKIMessage generateIRorKUR(int reqType) throws Exception {

        if (reqType != PKIBody.TYPE_INIT_REQ && reqType != PKIBody.TYPE_KEY_UPDATE_REQ)
            throw new Exception("NOT SUPPORTED CERT REQUEST TYPE");

        PKIMessage pKIMessage = null;
        PKIHeader pkiHeader = null;
        PKIBody pkiBody = null;
        DERBitString signature = null;
        String transactionID = null;
        String senderNonce = generateNonce();

        String recipient = parameters.getRecipientSubjectDN() != null ? parameters.getRecipientSubjectDN() : parameters.getRecipientCA();
        GeneralName recipientGeneralName = new GeneralName(new X500Name(recipient));
        String sender = entityCert.getX509v3PKCert().getSubject().toString();
        GeneralName senderGeneralName = new GeneralName(new X500Name(sender));

        if (parameters.isSendTransactionID()) {
            if (parameters.getTransactionID() == null) {
                transactionID = generateTransactionID();
            }
        }
        pkiHeader = createPKIHeader(senderGeneralName, recipientGeneralName, senderNonce, null, transactionID, null);
        pkiHeader.getTransactionID();
        pkiBody = createPKIBodyForIRorKUR(reqType);

        signature = CMPUtil.signMessage(pkiHeader, pkiBody, parameters.getEntityCredential(), parameters.isValidProtectionBytes());

        if (parameters.getMode() == WorkingMode.WRONG_DIGITAL_SIGN_IR) {
            signature = new DERBitString("THIS IS REALLY NOT A SIGNATURE".getBytes());
        }

        pKIMessage = new PKIMessage(pkiHeader, pkiBody, signature, new CMPCertificate[] { entityCert });

        return pKIMessage;
    }

    private PKIBody createPKIBodyForIRorKUR(int requestType) throws Exception {
        PKIBody pkiBody = null;
        OptionalValidity optValidity = null;
        Extensions extensions = null;
        final SubjectPublicKeyInfo publicKeyInfo;
        final CertTemplate certTemplate;
        final CertReqMsg message;

        optValidity = buildOptionalValidity();
        extensions = buildCertificateExtensions();
        publicKeyInfo = retrievePublicKeyInfo();

        final CertTemplateBuilder ctBuilder = new CertTemplateBuilder();

        String recipient = parameters.getRecipientSubjectDN() != null ? parameters.getRecipientSubjectDN() : parameters.getRecipientCA();
        ctBuilder.setIssuer(new X500Name(recipient));

        ctBuilder.setValidity(optValidity);

        ctBuilder.setSubject(new X500Name(parameters.getNodeName()));

        ctBuilder.setExtensions(extensions);

        ctBuilder.setPublicKey(publicKeyInfo);
        certTemplate = ctBuilder.build();
        message = formCertificateRequestMsg(certTemplate);
        final CertReqMessages messages = new CertReqMessages(message);

        //pkiBody = new PKIBody(requestType, messages);

        if (parameters.isValidRequestType()) {
            pkiBody = new PKIBody(requestType, messages);
        } else {
            pkiBody = new PKIBody(PKIBody.TYPE_CROSS_CERT_REQ, messages);
        }

        return pkiBody;
    }

    private CertReqMsg formCertificateRequestMsg(CertTemplate certTemplate) throws OperatorCreationException {

        final CertRequest certRequest = new CertRequest(CERT_REQ_ID, certTemplate, null);
        final ProofOfPossessionSigningKeyBuilder poposkBuilder = new ProofOfPossessionSigningKeyBuilder(certRequest);
        final POPOSigningKey poposk = poposkBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(ownKeyPair.getPrivate()));
        final ProofOfPossession popo = new ProofOfPossession(poposk);

        final CertReqMsg message = new CertReqMsg(certRequest, popo, null);
        return message;
    }

}
