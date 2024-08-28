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

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.OperatorCreationException;

import com.ericsson.oss.itpf.security.pki.common.test.certificates.CertDataHolder;
import com.ericsson.oss.itpf.security.pki.common.test.certificates.VendorCertificateGenerator;
import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;

public abstract class AbstractClientRequest implements ClientRequest {

    protected Parameters parameters;
    protected CMPCertificate entityCert;
    protected CertDataHolder rAcertDataHolder;
    protected PKIMessage initialMessage;
    protected int requestType = 0;

    protected AbstractClientRequest(final Parameters params) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, OperatorCreationException, NoSuchProviderException,
            SignatureException, IOException {
        parameters = params;
        if (params.getEntityCredential() == null) {
            final VendorCertificateGenerator vendorGenerator = new VendorCertificateGenerator(params);
            parameters.setEntityCredential(vendorGenerator.getVendorSignedCredentials());
            rAcertDataHolder = CertDataHolder.getRACertDataHolder(this.getClass().getResource(Constants.KEY_STORE_PATH).getPath());
        }
        entityCert = new CMPCertificate(parameters.getEntityCredential().getCert());
    }

    protected AbstractClientRequest(final Parameters params, final PKIMessage forInitialMessage) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, OperatorCreationException,
            NoSuchProviderException, SignatureException, IOException {
        parameters = params;
        initialMessage = forInitialMessage;
        requestType = forInitialMessage.getBody().getType();

        if (params.getEntityCredential() == null) {
            final VendorCertificateGenerator vendorGenerator = new VendorCertificateGenerator(params);
            parameters.setEntityCredential(vendorGenerator.getVendorSignedCredentials());
            rAcertDataHolder = CertDataHolder.getRACertDataHolder(this.getClass().getResource(Constants.KEY_STORE_PATH).getPath());
        }
        entityCert = new CMPCertificate(parameters.getEntityCredential().getCert());
    }

    protected GeneralName getRecipientGN() {
        final String recipient = parameters.getRecipientSubjectDN() != null ? parameters.getRecipientSubjectDN() : parameters.getRecipientCA();
        final GeneralName recipientGeneralName = new GeneralName(new X500Name(recipient));
        return recipientGeneralName;
    }

    protected GeneralName getSenderNameGN() {
        final String sender = entityCert.getX509v3PKCert().getSubject().toString();
        final GeneralName senderGeneralName = new GeneralName(new X500Name(sender));
        return senderGeneralName;
    }

    public CertTemplate buildCertTemplate(final OptionalValidity optValidity, final Extensions extensions, final SubjectPublicKeyInfo publicKeyInfo) {
        final String recipient = parameters.getRecipientSubjectDN() != null ? parameters.getRecipientSubjectDN() : parameters.getRecipientCA();
        final CertTemplateBuilder ctBuilder = new CertTemplateBuilder();
        ctBuilder.setIssuer(new X500Name(recipient));
        ctBuilder.setValidity(optValidity);
        ctBuilder.setSubject(new X500Name(parameters.getNodeName()));
        ctBuilder.setExtensions(extensions);
        ctBuilder.setPublicKey(publicKeyInfo);
        final CertTemplate certTemplate = ctBuilder.build();
        return certTemplate;
    }

}
