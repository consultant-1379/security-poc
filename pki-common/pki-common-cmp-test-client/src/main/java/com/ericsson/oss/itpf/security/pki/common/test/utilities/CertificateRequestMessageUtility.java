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
package com.ericsson.oss.itpf.security.pki.common.test.utilities;

import java.io.*;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;

public class CertificateRequestMessageUtility {

    public static CertReqMsg formCertificateRequestMsg(final CertTemplate certTemplate, final Parameters parameters) throws OperatorCreationException, NoSuchAlgorithmException {

        final CertRequest certRequest = new CertRequest(Constants.CERT_REQUEST_ID, certTemplate, null);
        final ProofOfPossessionSigningKeyBuilder poposkBuilder = new ProofOfPossessionSigningKeyBuilder(certRequest);
        final KeyPair keyPair = KeyStoreUtility.generateKeyPair(parameters.getKeyAlgorithm(), parameters.getKeyLengthInRequest());
        final POPOSigningKey poposk = poposkBuilder.build(new JcaContentSignerBuilder(Constants.SIGNING_ALGORITHM).setProvider(Constants.BC_SECURITY_PROVIDER).build(keyPair.getPrivate()));
        final ProofOfPossession popo = new ProofOfPossession(poposk);
        final CertReqMsg message = new CertReqMsg(certRequest, popo, null);
        return message;
    }

    public static OptionalValidity buildOptionalValidity(final Parameters parameters) {
        final Calendar notbefore = Calendar.getInstance();
        notbefore.add(Calendar.MINUTE, (parameters.getPostponeInMinutes() > 0) ? parameters.getPostponeInMinutes() : 0);

        final Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, (parameters.getValidityInMinutes() > 0) ? parameters.getValidityInMinutes() : 4320);

        final Time notafter = new Time(calendar.getTime());
        final ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DERTaggedObject(0, new Time(notbefore.getTime())));
        vector.add(new DERTaggedObject(1, notafter));

        final OptionalValidity optValidity = OptionalValidity.getInstance(new DERSequence(vector));
        return optValidity;

    }

    public static Extensions buildCertificateExtensions() throws IOException {
        final GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.dNSName, "test.ericsson"));
        ByteArrayOutputStream bOut = null;
        ASN1OutputStream dOut = null;
        Extensions extensions = null;
        try {
            bOut = new ByteArrayOutputStream();
            dOut = ASN1OutputStream.create(bOut, ASN1Encoding.DER);
            dOut.writeObject(subjectAltName);
            final byte[] valu = bOut.toByteArray();
            final Extension extension = new Extension(Extension.subjectAlternativeName, true, valu);
            extensions = new Extensions(extension);
        } finally {
            if (dOut != null) {
                dOut.close();
            }
            if (bOut != null) {
                bOut.close();
            }
        }
        return extensions;
    }

    public static SubjectPublicKeyInfo retrievePublicKeyInfo(final Parameters parameters) throws IOException, NoSuchAlgorithmException {
        final KeyPair keyPair = KeyStoreUtility.generateKeyPair(parameters.getKeyAlgorithm(), parameters.getKeyLengthInRequest());
        final byte[] bytes = keyPair.getPublic().getEncoded();
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        final ASN1InputStream asn1InputStream = new ASN1InputStream(byteArrayInputStream);
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance((ASN1Sequence) asn1InputStream.readObject());
        asn1InputStream.close();
        byteArrayInputStream.close();
        return publicKeyInfo;
    }

}
