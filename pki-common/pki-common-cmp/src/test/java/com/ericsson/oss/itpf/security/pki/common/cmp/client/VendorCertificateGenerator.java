package com.ericsson.oss.itpf.security.pki.common.cmp.client;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

public class VendorCertificateGenerator {

    private KeyPair generatedKeypair;
    private X509Certificate x509Certificate;

    private X509Certificate vendorCACert;
    private KeyPair vendorKeyPair;

    private PKCS10CertificationRequest pKCS10CertificationRequest;
    private final Parameters parameters;

    public VendorCertificateGenerator(final Parameters params) throws Exception {

        String vendorCACertPath = null;
        String vendorKeyPath = null;

        parameters = params;

        // vendorKeyPath = this.getClass().getResource("/CertificatesTest/" + parameters.getVendorTrustedCA() + ".key").getPath();
        vendorKeyPath = "src/test/resources/CertificatesTest/MyRoot.key";
        vendorKeyPair = getKeys(vendorKeyPath);

        // vendorCACertPath = this.getClass().getResource("/CertificatesTest/" + parameters.getVendorTrustedCA() + ".crt").getPath();
        vendorCACertPath = "src/test/resources/CertificatesTest/MyRoot.crt";
        vendorCACert = readCertificateFromPath(vendorCACertPath);

        // Assert that the private key matches the public key in the cert
        final Signature sig = Signature.getInstance("SHA1withRSA", "BC");
        sig.initSign(vendorKeyPair.getPrivate());
        final String testString = "testString";
        sig.update(testString.getBytes());
        final byte[] signature = sig.sign();

        final Signature signatureVerifier = Signature.getInstance("SHA1withRSA", "BC");

        signatureVerifier.initVerify(vendorCACert.getPublicKey());
        signatureVerifier.update(testString.getBytes());

        if (!signatureVerifier.verify(signature)) {
            throw new Exception("CA public key - private key mismatch");
        }

        generatedKeypair = CMPUtil.generateKeyPair(parameters.getKeyAlgorithm(), parameters.getKeySize());

        buildPKCSCeritificationRequest();
        buildX509Certificate();
    }

    // REVIEW: Name change
    private X509Certificate readCertificateFromPath(final String certificateFilePath) throws IOException, CertificateException {

        FileInputStream fileInputStream = null;
        X509Certificate x509Certificate = null;
        try {
            fileInputStream = new FileInputStream(certificateFilePath);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
        } finally {
            if (fileInputStream != null) {
                fileInputStream.close();
            }
        }
        return x509Certificate;
    }

    // REVIEW: Changed methodName
    private void buildPKCSCeritificationRequest() throws OperatorCreationException, IOException {

        SubjectPublicKeyInfo keyInfo;
        final ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(generatedKeypair.getPublic().getEncoded()));
        final X500Name subjectDN = new X500Name(parameters.getNodeName());
        try {

            keyInfo = new SubjectPublicKeyInfo((ASN1Sequence) asn1InputStream.readObject());
        } finally {
            asn1InputStream.close();
        }
        final PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(subjectDN, keyInfo);

        final ContentSigner contentSigner = new JcaContentSignerBuilder(parameters.getSignatureAlgorithm()).setProvider("BC").build(generatedKeypair.getPrivate());

        pKCS10CertificationRequest = csrBuilder.build(contentSigner);

    }

    private KeyPair getKeys(final String keyFile) throws Exception {

        final PEMParser pemParser = new PEMParser(new FileReader(keyFile));
        KeyPair result = null;
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        try {
            Object obj;
            while ((obj = pemParser.readObject()) != null) {
                if (obj instanceof PEMKeyPair) {
                    result = converter.getKeyPair((PEMKeyPair) obj);

                } else {
                    throw new Exception("Not key file!");
                }
            }
        } finally {
            pemParser.close();
        }
        return result;
    }

    private X509v3CertificateBuilder getCertificateBuilder() throws IOException {

        final SubjectPublicKeyInfo keyInfo = pKCS10CertificationRequest.getSubjectPublicKeyInfo();

        final Calendar cal = Calendar.getInstance();
        final Date notbefore = cal.getTime();
        cal.add(Calendar.YEAR, 2);
        final Date notafter = cal.getTime();
        final BigInteger serial = new BigInteger(String.valueOf(parameters.getThreadId()));
        final X500Name caDN = new X500Name(vendorCACert.getSubjectDN().getName());

        final X509v3CertificateBuilder x509CertificateBuilder = new X509v3CertificateBuilder(caDN, serial, notbefore, notafter, pKCS10CertificationRequest.getSubject(), keyInfo);

        return x509CertificateBuilder;

    }

    // REVIEW: Name change and broken down into two mehods getCertificateBuilder
    private void buildX509Certificate() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, OperatorCreationException, CertificateException {

        final X509v3CertificateBuilder x509CertificateBuilder = getCertificateBuilder();
        generateCertificateFromX509CertificateBuilder(x509CertificateBuilder);

    }

    private void generateCertificateFromX509CertificateBuilder(X509v3CertificateBuilder x509CertificateBuilder) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, IOException, OperatorCreationException, CertificateException {

        final AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        final AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        final AsymmetricKeyParameter parameterCa = PrivateKeyFactory.createKey(vendorKeyPair.getPrivate().getEncoded());
        final SubjectPublicKeyInfo keyInfo = pKCS10CertificationRequest.getSubjectPublicKeyInfo();
        final ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(parameterCa);

        final SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyInfo);
        final KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.digitalSignature);

        x509CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        x509CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(vendorCACert));

        x509CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);

        x509CertificateBuilder.addExtension(Extension.keyUsage, true, keyUsage);

        final X509CertificateHolder holder = x509CertificateBuilder.build(sigGen);

        x509Certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(holder.getEncoded()));

    }

    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    public KeyPair getkeypair() {
        return generatedKeypair;
    }

    public CertDataHolder getVendorSignedCredentials() throws Exception {

        if (x509Certificate != null && generatedKeypair != null) {
            return new CertDataHolder(Certificate.getInstance(x509Certificate.getEncoded()), generatedKeypair);
        }
        throw new Exception("Cert or keypair is NULL");
    }

}
