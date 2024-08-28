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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateRequestMessageSetUPData {

    private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

    public static final String KEY_GEN_ALGORITHM = "RSA";

    private static final String PROVIDER = "BC";

    public static final String ROOT_CA = "RootCA";

    private final SetUPData setUPData = new SetUPData();

    /**
     * Generates CertificateRequestMessage by passing subject, SAN EXTENSION.
     * 
     * @param subject
     *            subject for the CSR.
     * @param sanAttributes
     *            list of sanAttributes to generate DERSet.
     * @return returns generated CertificateRequestMessage object.
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     * @throws OperatorCreationException
     */
    public CertificateRequestMessage generateCRMFRequest(final X500Name subject, final String sanExtension) throws NoSuchAlgorithmException, IOException, OperatorCreationException {
        final KeyPair keyPair = setUPData.generateKeyPair(KEY_GEN_ALGORITHM, 2048);
        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        final int CERT_REQ_ID = 1;
        final CertTemplateBuilder ctBuilder = new CertTemplateBuilder();
        ctBuilder.setIssuer(new X500Name("CN=ENMSubCA"));
        ctBuilder.setSubject(subject);
        Extensions extensions = null;
        if (sanExtension != null) {
            final GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.dNSName, sanExtension));
            final ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            ASN1OutputStream.create(bOut, ASN1Encoding.DER).writeObject(subjectAltName);
            final byte[] valu = bOut.toByteArray();

            final Extension extension = new Extension(Extension.subjectAlternativeName, true, valu);
            extensions = new Extensions(extension);
        }

        ctBuilder.setExtensions(extensions);
        ctBuilder.setPublicKey(subjectPublicKeyInfo);

        final CertRequest certRequest = new CertRequest(CERT_REQ_ID, ctBuilder.build(), null);

        final ProofOfPossessionSigningKeyBuilder poposkBuilder = new ProofOfPossessionSigningKeyBuilder(certRequest);
        final POPOSigningKey poposk = poposkBuilder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER).build(keyPair.getPrivate()));
        final ProofOfPossession popo = new ProofOfPossession(poposk);

        final CertReqMsg message = new CertReqMsg(certRequest, popo, null);
        final CertificateRequestMessage certificateRequestMessage = new CertificateRequestMessage(message);
        return certificateRequestMessage;
    }

    public CertificateRequestMessage generateCRMFRequest(final GeneralName[] generalNames) throws NoSuchAlgorithmException, IOException, OperatorCreationException {
        final KeyPair keyPair = setUPData.generateKeyPair(KEY_GEN_ALGORITHM, 2048);
        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        final int CERT_REQ_ID = 1;
        final CertTemplateBuilder ctBuilder = new CertTemplateBuilder();
        final X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBld.addRDN(BCStyle.CN, ROOT_CA);
        final X500Name subject = x500NameBld.build();
        ctBuilder.setIssuer(new X500Name("CN=TestRecp"));
        ctBuilder.setSubject(subject);

        final GeneralNames subjectAltName = new GeneralNames(generalNames);
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        ASN1OutputStream.create(bOut, ASN1Encoding.DER).writeObject(subjectAltName);
        final byte[] valu = bOut.toByteArray();

        final Extension extension = new Extension(Extension.subjectAlternativeName, true, valu);
        final Extensions extensions = new Extensions(extension);
        ctBuilder.setExtensions(extensions);
        ctBuilder.setPublicKey(subjectPublicKeyInfo);

        final CertRequest certRequest = new CertRequest(CERT_REQ_ID, ctBuilder.build(), null);

        final ProofOfPossessionSigningKeyBuilder poposkBuilder = new ProofOfPossessionSigningKeyBuilder(certRequest);
        final POPOSigningKey poposk = poposkBuilder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER).build(keyPair.getPrivate()));
        final ProofOfPossession popo = new ProofOfPossession(poposk);

        final CertReqMsg message = new CertReqMsg(certRequest, popo, null);
        final CertificateRequestMessage certificateRequestMessage = new CertificateRequestMessage(message);
        return certificateRequestMessage;
    }

    /**
     * Generates CertificateRequestMessage with all extensions.
     * 
     * @throws IOException
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     * 
     * 
     */
    public CertificateRequestMessage generateCRMFRequestwithAllExtensions() throws NoSuchAlgorithmException, OperatorCreationException, IOException {

        GeneralName[] subjectAltName = new GeneralName[9];
        subjectAltName[0] = new GeneralName(GeneralName.dNSName, "abc.com");
        subjectAltName[1] = new GeneralName(GeneralName.directoryName, "CN=dir");
        subjectAltName[2] = new GeneralName(GeneralName.iPAddress, "201.13.14.15");
        subjectAltName[3] = new GeneralName(GeneralName.rfc822Name, "rfc");
        subjectAltName[4] = new GeneralName(GeneralName.directoryName, new X500Name("CN=RootCA"));
        subjectAltName[5] = new GeneralName(GeneralName.uniformResourceIdentifier, "www.ericsson.se");

        final DERTaggedObject ediPartyName = new DERTaggedObject(GeneralName.ediPartyName, new DERPrintableString("edi"));
        subjectAltName[6] = GeneralName.getInstance(ediPartyName);

        final DERTaggedObject otherName = new DERTaggedObject(GeneralName.otherName, new DERPrintableString("other"));
        subjectAltName[7] = GeneralName.getInstance(otherName);
        subjectAltName[8] = new GeneralName(GeneralName.registeredID, new ASN1ObjectIdentifier("2.100.3"));

        return generateCRMFRequest(subjectAltName);

    }
}
