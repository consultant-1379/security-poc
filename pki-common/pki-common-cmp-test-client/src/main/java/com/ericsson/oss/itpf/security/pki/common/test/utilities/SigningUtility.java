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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import com.ericsson.oss.itpf.security.pki.common.test.certificates.CertDataHolder;
import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;

public class SigningUtility {

    public static DERBitString signMessageUsingIAK(final PKIHeader header, final PKIBody body, final String IAKValue) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            IOException {

        final PBMParameter pbmParameter = PBMParameter.getInstance(header.getProtectionAlg().getParameters());
        final String owfId = pbmParameter.getOwf().getAlgorithm().getId();
        final String macOid = pbmParameter.getMac().getAlgorithm().getId();
        final int iterationCount = pbmParameter.getIterationCount().getPositiveValue().intValue();
        final byte[] saltOctets = pbmParameter.getSalt().getOctets();
        final AlgorithmIdentifier owfAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier(owfId));

        byte[] basekey = calculateProtectionBytes(IAKValue, saltOctets);
        basekey = constructBaseKey(iterationCount, owfAlg, basekey);

        final Mac mac = updateMac(header, body, macOid, basekey);
        final byte[] resetedMac = mac.doFinal();
        final DERBitString signature = new DERBitString(resetedMac);

        return signature;

    }

    public static DERBitString signMessage(final PKIHeader header, final PKIBody body, final CertDataHolder certData, final boolean isValidProtectionBytes) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeyException, SignatureException, IOException {

        final AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        final Signature signature = Signature.getInstance(algorithmIdentifier.getAlgorithm().getId(), Constants.BC_SECURITY_PROVIDER);
        signature.initSign(certData.getKeyPair().getPrivate());
        final ProtectedPart protectedPart = new ProtectedPart(header, body);

        if (!isValidProtectionBytes) {
            final byte[] invalidBytes = new byte[] { 100, 22, 44, 112 };
            signature.update(invalidBytes);
        }

        signature.update(protectedPart.getEncoded());

        return new DERBitString(signature.sign());

    }

    public static AlgorithmIdentifier getAlgorithmIdentifierForIAK() {
        final AlgorithmIdentifier owfAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"));
        final int iterationCount = 567;
        final AlgorithmIdentifier macAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.7"));
        final byte[] salt = "dummySalt123".getBytes();
        final DEROctetString derSalt = new DEROctetString(salt);
        final ASN1Integer iteration = new ASN1Integer(iterationCount);
        final String objectId = "1.2.840.113533.7.66.13";
        final PBMParameter pbmParameter = new PBMParameter(derSalt, owfAlg, iteration, macAlg);
        final AlgorithmIdentifier protectionAlgorithmID = new AlgorithmIdentifier(new ASN1ObjectIdentifier(objectId), pbmParameter);

        return protectionAlgorithmID;

    }

    public static byte[] getProtectedBytes(final PKIHeader header, final PKIBody body) throws IOException {
        byte[] protectionBytes = null;
        final ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
        asn1EncodableVector.add(header);
        asn1EncodableVector.add(body);

        final ASN1Encodable protectedPart = new DERSequence(asn1EncodableVector);
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ASN1OutputStream derOutputStream = null;
        derOutputStream = ASN1OutputStream.create(byteArrayOutputStream, ASN1Encoding.DER);
        derOutputStream.writeObject(protectedPart);
        protectionBytes = byteArrayOutputStream.toByteArray();
        derOutputStream.close();
        byteArrayOutputStream.close();
        return protectionBytes;
    }

    private static Mac updateMac(final PKIHeader header, final PKIBody body, final String macOid, final byte[] basekey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            IOException {
        final byte[] protectedBytes = getProtectedBytes(header, body);
        final Mac mac = Mac.getInstance(macOid, Constants.BC_SECURITY_PROVIDER);
        final SecretKey key = new SecretKeySpec(basekey, macOid);
        mac.init(key);
        mac.reset();
        mac.update(protectedBytes, 0, protectedBytes.length);
        return mac;
    }

    private static byte[] constructBaseKey(final int iterationCount, final AlgorithmIdentifier owfAlg, final byte[] basekey) throws NoSuchAlgorithmException, NoSuchProviderException {
        final MessageDigest dig = MessageDigest.getInstance(owfAlg.getAlgorithm().getId(), Constants.BC_SECURITY_PROVIDER);
        byte[] hashBaseKey = basekey;
        for (int i = 0; i < iterationCount; i++) {
            hashBaseKey = dig.digest(hashBaseKey);
            dig.reset();
        }
        return hashBaseKey;
    }

    private static byte[] calculateProtectionBytes(final String IAKValue, final byte[] saltOctets) {
        final byte[] raSecret = IAKValue.getBytes();
        final byte basekey[] = new byte[raSecret.length + saltOctets.length];
        System.arraycopy(raSecret, 0, basekey, 0, raSecret.length);
        System.arraycopy(saltOctets, 0, basekey, raSecret.length, saltOctets.length);
        return basekey;
    }

}
