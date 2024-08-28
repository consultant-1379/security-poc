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

import java.io.*;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.util.encoders.Base64;

public abstract class AbstractRequestResponse {

    protected static SecureRandom secureRandom;
    protected Parameters parameters;
    protected KeyPair ownKeyPair;
    protected static final int CERT_REQ_ID = 1;

    protected CMPCertificate entityCert;
    protected CertDataHolder rAcertDataHolder;

    public enum WorkingMode {
        POSITIVE_IR, WRONG_DIGITAL_SIGN_IR
    }

    protected AbstractRequestResponse(Parameters params) throws Exception {

        String rAKeyAndCertPath = null;
        secureRandom = new SecureRandom();
        parameters = params;

        if (params.getEntityCredential() == null) {
            VendorCertificateGenerator vendorGenerator = new VendorCertificateGenerator(params);
            parameters.setEntityCredential(vendorGenerator.getVendorSignedCredentials());
            //   rAKeyAndCertPath = this.getClass().getResource("/CertificatesTest/" + "racsa_omsas.jks").getPath();
            rAKeyAndCertPath = "src/test/resources/CertificatesTest/racsa_omsas.jks";
            rAcertDataHolder = CMPUtil.getRACertDataHolder(rAKeyAndCertPath);
        }

        entityCert = new CMPCertificate(parameters.getEntityCredential().getCert());

        ownKeyPair = CMPUtil.generateKeyPair(parameters.getKeyAlgorithm(), parameters.getKeyLengthInRequest());

    }

    protected String convertASN1OctetStringToString(ASN1OctetString asn1OctetString) throws IOException {
        String data = new String(Base64.encode(asn1OctetString.getOctets()));
        return data;
    }

    protected String generateNonce() {
        byte[] noncebytes = new byte[16];
        secureRandom.nextBytes(noncebytes);
        return new String(Base64.encode(noncebytes));
    }

    protected String generateTransactionID() {
        byte[] transactionBytes = new byte[16];
        secureRandom.nextBytes(transactionBytes);
        return new String(Base64.encode(transactionBytes));
    }

    protected PKIHeader createPKIHeader(final GeneralName sender, final GeneralName recipient, final String senderNonce, final String recipientNonce, final String transactionId,
            AlgorithmIdentifier algorithmIdentifier) {

        PKIHeaderBuilder pKIHeaderBuilder = null;
        PKIHeader pkiHeader = null;
        boolean isValidHeader = parameters.isValidHeader();
        boolean isInDirectoryFormat = parameters.isInDirectoryFormat();
        boolean isValidProtectionAlgo = parameters.isValidProtectionAlgo();

        int headerVersion = PKIHeader.CMP_2000;
        if (!isValidHeader)
            headerVersion = PKIHeader.CMP_1999;

        if (isInDirectoryFormat) {
            pKIHeaderBuilder = new PKIHeaderBuilder(headerVersion, sender, recipient);
        } else {
            pKIHeaderBuilder = new PKIHeaderBuilder(headerVersion, new GeneralName(GeneralName.dNSName, "CN=Entity"), new GeneralName(GeneralName.dNSName, "CN=Entity"));
        }

        if (!isValidProtectionAlgo) {
            String invalidProtectionAlgorithmID = "1.2.840.113549.1.6";
            ASN1ObjectIdentifier objID = new ASN1ObjectIdentifier(invalidProtectionAlgorithmID);
            pKIHeaderBuilder.setProtectionAlg(new AlgorithmIdentifier(objID));
        } else {
            if (algorithmIdentifier == null) {
                pKIHeaderBuilder.setProtectionAlg(new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption));
            } else {
                pKIHeaderBuilder.setProtectionAlg(algorithmIdentifier);
            }
        }

        pKIHeaderBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));
        if (senderNonce != null) {
            pKIHeaderBuilder.setSenderNonce(new DEROctetString(Base64.decode(senderNonce.getBytes())));
        }
        if (recipientNonce != null) {
            pKIHeaderBuilder.setRecipNonce(new DEROctetString(Base64.decode(recipientNonce.getBytes())));
        }
        if (transactionId != null) {
            pKIHeaderBuilder.setTransactionID(new DEROctetString(Base64.decode(transactionId.getBytes())));
        }

        pkiHeader = pKIHeaderBuilder.build();

        return pkiHeader;
    }

    protected OptionalValidity buildOptionalValidity() {
        Calendar notbefore = Calendar.getInstance();
        notbefore.add(Calendar.MINUTE, (parameters.getPostponeInMinutes() > 0) ? parameters.getPostponeInMinutes() : 0);

        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MINUTE, (parameters.getValidityInMinutes() > 0) ? parameters.getValidityInMinutes() : 4320);
        final Time notafter = new Time(cal.getTime());

        final ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DERTaggedObject(0, new Time(notbefore.getTime())));
        vector.add(new DERTaggedObject(1, notafter));

        final OptionalValidity optValidity = OptionalValidity.getInstance(new DERSequence(vector));
        return optValidity;

    }

    protected SubjectPublicKeyInfo retrievePublicKeyInfo() throws IOException {
        final byte[] bytes = ownKeyPair.getPublic().getEncoded();
        final ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        final ASN1InputStream dIn = new ASN1InputStream(bIn);
        final SubjectPublicKeyInfo publicKeyInfo;
        try {
            publicKeyInfo = new SubjectPublicKeyInfo((ASN1Sequence) dIn.readObject());
        } finally {
            dIn.close();
        }
        return publicKeyInfo;
    }

    protected Extensions buildCertificateExtensions() throws IOException {

        GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.dNSName, "test.ericsson"));
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream dOut = null;
        dOut = ASN1OutputStream.create(bOut, ASN1Encoding.DER);
        dOut.writeObject(subjectAltName);
        byte[] valu = bOut.toByteArray();

        Extension extension = new Extension(Extension.subjectAlternativeName, true, valu);
        Extensions extn = new Extensions(extension);
        return extn;
    }

}
