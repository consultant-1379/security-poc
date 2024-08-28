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
import java.util.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;

public class PKCS10CertificationRequestSetUPData {

    private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";

    public static final String KEY_GEN_ALGORITHM = "RSA";

    private static final String CHALLENGE_PASSWORD = "password";

    private static final String PROVIDER = "BC";

    public static final String ROOT_CA = "RootCA";

    private final SetUPData setUPData = new SetUPData();

    /**
     * Method to generate PKCS10CertificationRequest using list of generalNames.
     * 
     * @param generalNames
     *            list of GeneralName values.
     * @return PKCS10CertificationRequest PKCS10CertificateRequest object prepared from list of general names.
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws OperatorCreationException
     */
    public PKCS10CertificationRequest generatePKCS10Request(final List<GeneralName> generalNames) throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeyException,
            NoSuchProviderException, OperatorCreationException {

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_GEN_ALGORITHM, PROVIDER);
        kpg.initialize(1024);
        final KeyPair kp = kpg.genKeyPair();

        final X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBld.addRDN(BCStyle.CN, ROOT_CA);
        final X500Name subject = x500NameBld.build();

        final PKCS10CertificationRequestBuilder requestBuilder = createPKCS10ReqBuilder(generalNames, kp, subject);
        return requestBuilder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER).build(kp.getPrivate()));

    }

    /**
     * Method to create PKCS10CertificationRequestBuilder by passing list of generalNames, KeyPair, subject.
     * 
     * @param generalNames
     *            list of generalNames to add into the extension
     * @param kp
     *            KeyPair object.
     * @param subject
     *            subject value passed to create PKCS10CertificationRequestBuilder
     * @return returns generated PKCS10CertificationRequestBuilder object.
     * @throws IOException
     */
    private PKCS10CertificationRequestBuilder createPKCS10ReqBuilder(final List<GeneralName> generalNames, final KeyPair kp, final X500Name subject) throws IOException {
        final PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());

        final ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(generalNames.toArray(new GeneralName[0])));
        requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        return requestBuilder;
    }

    /**
     * Generates PKCS10CertificationRequest with extension attributes.
     * 
     * @return returns PKCS10CertificationRequest. PKCS10CertificateRequest object prepared.
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws OperatorCreationException
     */
    public PKCS10CertificationRequest generatePKCS10Requestwithattributes() throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeyException, NoSuchProviderException,
            OperatorCreationException {

        GeneralName[] subjectAltName = new GeneralName[8];
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

        return generatePKCS10Request(Arrays.asList(subjectAltName));

    }

    /**
     * Generates PKCS10CertificationRequest by passing subject, list of SAN attributes.
     * 
     * @param subject
     *            subject for the CSR.
     * @param sanAttributes
     *            list of sanAttributes to generate DERSet.
     * @return returns generated PKCS10CertificationRequest object.
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     * @throws InvalidKeyException
     */
    public PKCS10CertificationRequest generatePKCS10Request(final X500Name subject, final String... sanAttributes) throws NoSuchAlgorithmException, SignatureException, IOException,
            InvalidKeyException {

        final KeyPair keyPair = setUPData.generateKeyPair(KEY_GEN_ALGORITHM, 2048);
        final AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIGNATURE_ALGORITHM);
        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        final DERSet attributes = getDERSet(sanAttributes);

        final CertificationRequestInfo certificationRequestInfo = new CertificationRequestInfo(subject, subjectPublicKeyInfo, attributes);
        final Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(keyPair.getPrivate());
        signature.update(certificationRequestInfo.getEncoded(ASN1Encoding.DER));

        final DERBitString signatureBits = new DERBitString(signature.sign());
        final CertificationRequest certificationRequest = new CertificationRequest(certificationRequestInfo, sigAlgId, signatureBits);
        final PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(certificationRequest);
        return pkcs10CertificationRequest;
    }

    /**
     * Generates DERSet based on the list of String values
     * 
     * @param sanAttributes
     *            prepares GeneralName based on sanAttributes
     * @return return DERSet Object
     */
    public DERSet getDERSet(final String... sanAttributes) {
        DERSet attributes = null;
        if (sanAttributes != null) {
            final ASN1EncodableVector extensionattr = new ASN1EncodableVector();
            extensionattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);

            final GeneralNames san = createGeneralNamesForSAN(sanAttributes);

            final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            try {
            	ASN1OutputStream.create(bOut, ASN1Encoding.DER).writeObject(san);
            } catch (IOException e) {
                throw new CertificateRequestGenerationException("error encoding value: " + e);
            }

            attributes = createDERSet(extensionattr, bOut);
        }
        return attributes;
    }

    /**
     * Generates GeneralNames based on list of sanAttributes values
     * 
     * @param sanAttributes
     *            prepares GeneralName based on sanAttributes
     * @return returns list of GeneralNames
     */
    private GeneralNames createGeneralNamesForSAN(final String... sanAttributes) {
        GeneralName[] subjectAltName = new GeneralName[sanAttributes.length];
        for (int i = 0; i < subjectAltName.length; i++) {
            subjectAltName[i] = new GeneralName(GeneralName.dNSName, new DERPrintableString(sanAttributes[i]));
        }
        final GeneralNames san = new GeneralNames(subjectAltName);
        return san;
    }

    /**
     * Creates DERSet by passing ASN1EncodableVector,ByteArrayOutputStream.
     * 
     * @param extensionattr
     *            It will add X509Extensions.
     * @param bOut
     * @return returns DERSet object. returns DERSet object.
     */
    private DERSet createDERSet(final ASN1EncodableVector extensionattr, final ByteArrayOutputStream bOut) {
        DERSet attributes;
        final Vector oidvec = new Vector();
        oidvec.add(Extension.subjectAlternativeName);
        final Vector valuevec = new Vector();
        valuevec.add(new X509Extension(false, new DEROctetString(bOut.toByteArray())));
        final X509Extensions exts = new X509Extensions(oidvec, valuevec);
        extensionattr.add(new DERSet(exts));
        final ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERSequence(extensionattr));
        attributes = new DERSet(v);
        return attributes;
    }

    /**
     * Generates PKCS10CertificationRequest with challenge password.
     * 
     * @return returns generated PKCS10CertificationRequest object.
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     */
    public PKCS10CertificationRequest generatePKCS10RequestWithChallengePassword() throws NoSuchAlgorithmException, OperatorCreationException {
        final KeyPair keyPair = setUPData.generateKeyPair(KEY_GEN_ALGORITHM, 2048);

        final JcaContentSignerBuilder csb = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);
        final ContentSigner cs = csb.build(keyPair.getPrivate());
        final PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=RootCA"), keyPair.getPublic());

        final DERPrintableString password = new DERPrintableString(CHALLENGE_PASSWORD);
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);
        return csrBuilder.build(cs);

    }

}
