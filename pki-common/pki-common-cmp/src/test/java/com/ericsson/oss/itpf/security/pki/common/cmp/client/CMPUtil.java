package com.ericsson.oss.itpf.security.pki.common.cmp.client;

import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;

public class CMPUtil {
    static final String securityProvider = "BC";

    public static KeyPair generateKeyPair(final String keyAlgorithm, final int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = null;
        keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
        keyGen.initialize(keySize);
        final KeyPair keyPair = keyGen.genKeyPair();
        return keyPair;
    }

    public static DERBitString signMessage(final PKIHeader header, final PKIBody body, final CertDataHolder certData, final boolean isValidProtectionBytes) throws Exception {

        AlgorithmIdentifier algoId = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        final Signature sig = Signature.getInstance(algoId.getAlgorithm().getId(), securityProvider);
        sig.initSign(certData.getKeyPair().getPrivate());
        final ProtectedPart pp = new ProtectedPart(header, body);

        if (!isValidProtectionBytes) {
            byte[] invalidBytes = new byte[] { 100, 22, 44, 112 };
            sig.update(invalidBytes);
        }

        sig.update(pp.getEncoded());
        return new DERBitString(sig.sign());

    }

    public static CertDataHolder getRACertDataHolder(String filePath) throws Exception {

        final String KEYSTORE_ALIAS = "racsa_omsas";
        X509Certificate cert = null;
        PrivateKey key = null;
        KeyPair keyPair = null;
        CertDataHolder certDataHolder = null;

        KeyStore keyStore = KeyStore.getInstance("jks");
        File keyStorePath = new File(filePath);

        FileInputStream fileInputStream = null;
        try {
            fileInputStream = new FileInputStream(keyStorePath);
            keyStore.load(fileInputStream, new String(new byte[] { 115, 101, 99, 109, 103, 109, 116 }).toCharArray());

            key = (PrivateKey) keyStore.getKey(KEYSTORE_ALIAS, new String(new byte[] { 115, 101, 99, 109, 103, 109, 116 }).toCharArray());

            cert = (X509Certificate) keyStore.getCertificateChain(KEYSTORE_ALIAS)[0];
            keyPair = new KeyPair(cert.getPublicKey(), key);

            certDataHolder = new CertDataHolder(Certificate.getInstance(cert.getEncoded()), keyPair);
            java.security.cert.Certificate[] additionalCerts = keyStore.getCertificateChain(KEYSTORE_ALIAS);

            for (java.security.cert.Certificate additionalCert : additionalCerts) {
                certDataHolder.addAdditionalCert(additionalCert);
            }
        } finally {
            if (fileInputStream != null) {
                fileInputStream.close();
            }
        }
        return certDataHolder;
    }

}
