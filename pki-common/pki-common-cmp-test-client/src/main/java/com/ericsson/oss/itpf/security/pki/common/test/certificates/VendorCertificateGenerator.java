package com.ericsson.oss.itpf.security.pki.common.test.certificates;

import java.io.ByteArrayInputStream;
import java.io.IOException;
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
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.test.request.main.Parameters;
import com.ericsson.oss.itpf.security.pki.common.test.utilities.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.test.utilities.KeyStoreUtility;

public class VendorCertificateGenerator {

    private KeyPair generatedKeypair;
    private X509Certificate x509Certificate;

    private X509Certificate vendorCACert;
    private KeyPair vendorKeyPair;

    private PKCS10CertificationRequest pKCS10CertificationRequest;
    private final Parameters parameters;

    public VendorCertificateGenerator(final Parameters params) throws CertificateException, IOException, NoSuchAlgorithmException, OperatorCreationException, InvalidKeyException,
            NoSuchProviderException, SignatureException {
        parameters = params;
        final String vendorKeyPath = this.getClass().getResource("/CertificatesTest/" + parameters.getVendorTrustedCA() + ".key").getPath();
        final String vendorCACertPath = this.getClass().getResource("/CertificatesTest/" + parameters.getVendorTrustedCA() + ".crt").getPath();
        vendorKeyPair = KeyStoreUtility.getKeys(vendorKeyPath);
        vendorCACert = CertificateUtility.readCertificateFromPath(vendorCACertPath);
        generatedKeypair = KeyStoreUtility.generateKeyPair(parameters.getKeyAlgorithm(), parameters.getKeySize());
        buildPKCSCeritificationRequest();
        buildX509Certificate();
    }

    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    public KeyPair getkeypair() {
        return generatedKeypair;
    }

    public CertDataHolder getVendorSignedCredentials() throws CertificateEncodingException {
        CertDataHolder certDataHolder = null;
        if (x509Certificate != null && generatedKeypair != null) {
            certDataHolder = new CertDataHolder(Certificate.getInstance(x509Certificate.getEncoded()), generatedKeypair);
        }
        return certDataHolder;
    }

    private void buildPKCSCeritificationRequest() throws OperatorCreationException, IOException {
        final ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(generatedKeypair.getPublic().getEncoded()));
        final X500Name subjectDN = new X500Name(parameters.getNodeName());
        final SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence) asn1InputStream.readObject());
        asn1InputStream.close();
        final PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(subjectDN, keyInfo);
        final ContentSigner contentSigner = new JcaContentSignerBuilder(parameters.getSignatureAlgorithm()).setProvider(Constants.BC_SECURITY_PROVIDER).build(generatedKeypair.getPrivate());
        pKCS10CertificationRequest = csrBuilder.build(contentSigner);
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

    private void buildX509Certificate() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, OperatorCreationException, CertificateException {
        final X509v3CertificateBuilder x509CertificateBuilder = getCertificateBuilder();
        generateCertificateFromX509CertificateBuilder(x509CertificateBuilder);
    }

    private void generateCertificateFromX509CertificateBuilder(final X509v3CertificateBuilder x509CertificateBuilder) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException, IOException, OperatorCreationException, CertificateException {

        final AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(Constants.SIGNING_ALGORITHM);
        final AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        final AsymmetricKeyParameter parameterCa = PrivateKeyFactory.createKey(vendorKeyPair.getPrivate().getEncoded());
        final SubjectPublicKeyInfo keyInfo = pKCS10CertificationRequest.getSubjectPublicKeyInfo();
        final ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(parameterCa);
        final SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyInfo);
        final KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment);
        final X509CertificateHolder x509CertificateHolder = buildX509CertificateBuilder(x509CertificateBuilder, sigGen, subjectKeyIdentifier, keyUsage);

        ByteArrayInputStream bis = null;
        try {
            bis = new ByteArrayInputStream(x509CertificateHolder.getEncoded());
            x509Certificate = (X509Certificate) CertificateFactory.getInstance(Constants.CERTIFICATE_FACTORY, Constants.BC_SECURITY_PROVIDER).generateCertificate(bis);

        } finally {
            if (bis != null) {
                bis.close();
            }
        }
    }

    private X509CertificateHolder buildX509CertificateBuilder(final X509v3CertificateBuilder x509CertificateBuilder, final ContentSigner sigGen, final SubjectKeyIdentifier subjectKeyIdentifier,
            final KeyUsage keyUsage) throws CertIOException, CertificateEncodingException, NoSuchAlgorithmException {
        x509CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        x509CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(vendorCACert));
        x509CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
        x509CertificateBuilder.addExtension(Extension.keyUsage, true, keyUsage);
        final X509CertificateHolder x509CertificateHolder = x509CertificateBuilder.build(sigGen);

        return x509CertificateHolder;
    }

}
