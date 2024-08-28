/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.kaps.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.util.*;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.kaps.builder.*;
import com.ericsson.oss.itpf.security.kaps.certificate.exception.*;
import com.ericsson.oss.itpf.security.kaps.common.BaseTest;
import com.ericsson.oss.itpf.security.kaps.common.persistence.handler.KeyPairPersistenceHandler;
import com.ericsson.oss.itpf.security.kaps.common.utils.SignerUtility;
import com.ericsson.oss.itpf.security.kaps.crl.exception.InvalidCRLExtensionsException;
import com.ericsson.oss.itpf.security.kaps.crl.exception.SignCRLException;
import com.ericsson.oss.itpf.security.kaps.exception.CRLException;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.exception.NotSupportedException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.kaps.model.holder.*;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;

@RunWith(MockitoJUnitRunner.class)
public class KeyAccessProviderManagerTest extends BaseTest {

    @InjectMocks
    KeyAccessProviderManager keyAccessProviderManager;

    @Mock
    KeyPairPersistenceHandler keyPairPersistenceHandler;

    @Mock
    CertificateBuilder certificateBuilder;

    @Mock
    CSRBuilder csrBuilder;

    @Mock
    CRLBuilder crlBuilder;

    @Mock
    ASN1Set attributes;

    @Mock
    ASN1Encodable asn1;

    @Mock
    PKCS10CertificationRequest pkcs10CertificationRequest;

    @Mock
    PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder;

    @Mock
    X509v2CRLBuilder x509crlBuilder;

    private Algorithm signatureAlgorithm;

    private X500Name subject;
    private X500Name issuer;
    private Algorithm keyGenerationAlgorithm;
    private KeyIdentifier keyIdentifier;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private KeyPair keyPair;

    @Mock
    SignerUtility signerUtility;

    private CertificationRequestInfo certificationRequestInfo;
    List<CertificateExtensionHolder> CertificateExtensionHolder = null;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void setUp() throws NoSuchAlgorithmException, IOException {
        subject = new X500Name("CN=enmSecurity, O=Ericsson");
        issuer = new X500Name("CN=enmSecurity, O=Ericsson");
        keyGenerationAlgorithm = prepareKeyGenerationAlgorithm();
        keyIdentifier = new KeyIdentifier();
        keyIdentifier.setId("1");
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        CertificateExtensionHolder = buildCertificateExtensionholders();
        signatureAlgorithm = prepareSignatureAlgorithm();
    }

    @Test
    public void testGenerateKeyPair() throws KeyPairGenerationException, KeyAccessProviderServiceException {
        Mockito.when(keyPairPersistenceHandler.saveKeyPair(Mockito.anyString(), Mockito.anyInt(), Mockito.any(KeyPair.class))).thenReturn(keyIdentifier);
        keyAccessProviderManager.generateKeyPair(keyGenerationAlgorithm.getName(), keyGenerationAlgorithm.getKeySize());
    }

    @Test(expected = KeyPairGenerationException.class)
    public void testGenerateKeyPair_KeyPairGenerationException() throws KeyPairGenerationException, KeyAccessProviderServiceException {
        Mockito.when(keyPairPersistenceHandler.saveKeyPair(Mockito.anyString(), Mockito.anyInt(), Mockito.any(KeyPair.class))).thenThrow(new KeyPairGenerationException(""));
        keyAccessProviderManager.generateKeyPair("RSA123", 1234);
    }

    @Test
    public void testGetPublicKey() throws KeyIdentifierNotFoundException, KeyAccessProviderServiceException {
        Mockito.when(keyPairPersistenceHandler.getPublicKey(keyIdentifier)).thenReturn(publicKey);
        keyAccessProviderManager.getPublicKey(keyIdentifier);
    }

    @Test
    public void testGenerateCSR() throws CSRGenerationException, KeyIdentifierNotFoundException, KeyAccessProviderServiceException {
        final String signatureAlgorithm = "SHA256WithRSA";
        String subjectName = "CN=CN_PKI";
        Mockito.when(csrBuilder.buildPKCS10CertificationRequest(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.any(X500Name.class), Mockito.anyList())).thenReturn(
                pkcs10CertificationRequest);
        keyAccessProviderManager.generateCSR(keyIdentifier, signatureAlgorithm, subjectName, CertificateExtensionHolder);
    }

    @Test(expected = CSRGenerationException.class)
    public void testGenerateCSR_IOException() throws IOException, CSRGenerationException, KeyIdentifierNotFoundException, KeyAccessProviderServiceException {
        final String signatureAlgorithm = "SHA256WithRSA";
        String subjectName = "CN=CN_PKI";
        PKCS10CertificationRequest pkcs10CertificationRequest = Mockito.mock(PKCS10CertificationRequest.class);
        Mockito.doThrow(new IOException()).when(pkcs10CertificationRequest).getEncoded();
        Mockito.when(csrBuilder.buildPKCS10CertificationRequest(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.any(X500Name.class), Mockito.anyList())).thenReturn(
                pkcs10CertificationRequest);
        keyAccessProviderManager.generateCSR(keyIdentifier, signatureAlgorithm, subjectName, CertificateExtensionHolder);
    }

    @Test
    public void testSignCertificate() throws IOException, InvalidCertificateExtensionsException, KeyIdentifierNotFoundException, KeyAccessProviderServiceException, CertificateSignatureException {
        // final String signatureAlgorithm = "SHA256WithRSA";
        BigInteger serialNo = new BigInteger("123456789");
        Date notBefore = new Date();
        Date notAfter = new Date();

        final byte[] bytes = keyPair.getPublic().getEncoded();
        final ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        final ASN1InputStream dIn = new ASN1InputStream(bIn);
        final SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo((ASN1Sequence) dIn.readObject());

        final X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuer, serialNo, notBefore, notAfter, subject, publicKeyInfo);
        final X509v3CertificateBuilderHolder x509v3CertBuilderHolder = new X509v3CertificateBuilderHolder();
        x509v3CertBuilderHolder.setIssuerDN("CN=CN_PKI");
        x509v3CertBuilderHolder.setSerialNumber(new BigInteger("123456789"));
        x509v3CertBuilderHolder.setSubjectDN("CN=CN_PKI");
        x509v3CertBuilderHolder.setIssuerUniqueIdentifier(false);
        x509v3CertBuilderHolder.setSubjectUniqueIdentifier(true);
        x509v3CertBuilderHolder.setSubjectUniqueIdentifierValue("nmsadm");
        x509v3CertBuilderHolder.setSubjectPublicKey(publicKey);

        Mockito.when(certificateBuilder.buildX509v3CertificateBuilder(Mockito.any(X509v3CertificateBuilderHolder.class), Mockito.any(X500Principal.class))).thenReturn(x509v3CertificateBuilder);
        Mockito.when(keyPairPersistenceHandler.getPrivateKey(keyIdentifier)).thenReturn(privateKey);
        Mockito.when(signerUtility.getContentSigner(keyIdentifier, signatureAlgorithm.getName())).thenReturn(getContentSigner(privateKey, signatureAlgorithm.getName()));
        keyAccessProviderManager.signCertificate(keyIdentifier, signatureAlgorithm.getName(), x509v3CertBuilderHolder, new X500Principal("CN=" + "CN_PKI"));
    }

    @Test(expected = SignatureException.class)
        public void testSignCertificate_OperatorCreationException() throws IOException,
                        InvalidCertificateExtensionsException, KeyIdentifierNotFoundException, KeyAccessProviderServiceException,
                        com.ericsson.oss.itpf.security.kaps.common.exception.SignatureException, CertificateSignatureException {
        // final String signatureAlgorithm = "SHA256WithRSA";
        BigInteger serialNo = new BigInteger("123456789");
        Date notBefore = new Date();
        Date notAfter = new Date();

        final byte[] bytes = keyPair.getPublic().getEncoded();
        final ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        final ASN1InputStream dIn = new ASN1InputStream(bIn);
        final SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo((ASN1Sequence) dIn.readObject());

        final X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuer, serialNo, notBefore, notAfter, subject, publicKeyInfo);
        final X509v3CertificateBuilderHolder x509v3CertBuilderHolder = new X509v3CertificateBuilderHolder();
        x509v3CertBuilderHolder.setIssuerDN("CN=CN_PKI");
        x509v3CertBuilderHolder.setSerialNumber(new BigInteger("123456789"));
        x509v3CertBuilderHolder.setSubjectDN("CN=CN_PKI");
        x509v3CertBuilderHolder.setIssuerUniqueIdentifier(false);
        x509v3CertBuilderHolder.setSubjectUniqueIdentifier(true);
        x509v3CertBuilderHolder.setSubjectPublicKey(publicKey);

        Mockito.when(certificateBuilder.buildX509v3CertificateBuilder(Mockito.any(X509v3CertificateBuilderHolder.class), Mockito.any(X500Principal.class))).thenReturn(x509v3CertificateBuilder);
        Mockito.when(signerUtility.getContentSigner(keyIdentifier, signatureAlgorithm.getName())).thenThrow(SignatureException.class);
        keyAccessProviderManager.signCertificate(keyIdentifier, signatureAlgorithm.getName(), x509v3CertBuilderHolder, new X500Principal("CN=" + "CN_PKI"));
    }

    @Test
        public void testSignCRL() throws InvalidCRLExtensionsException, KeyIdentifierNotFoundException,
                KeyAccessProviderServiceException, SignCRLException {
        // final String signatureAlgorithm = "SHA256WithRSA";
        final X509v2CRLBuilderHolder x509v2CRLBuilderHolder = new X509v2CRLBuilderHolder();
        x509v2CRLBuilderHolder.setSubjectDN("CN=CN_PKI");
        final X509v2CRLBuilder x509crlBuilder = new X509v2CRLBuilder(subject, new Date());
        x509crlBuilder.setNextUpdate(new Date());
        Mockito.when(crlBuilder.buildX509v2CRLBuilder(Mockito.any(X509v2CRLBuilderHolder.class), Mockito.any(X500Principal.class))).thenReturn(x509crlBuilder);
        Mockito.when(keyPairPersistenceHandler.getPrivateKey(keyIdentifier)).thenReturn(privateKey);
        Mockito.when(signerUtility.getContentSigner(keyIdentifier, signatureAlgorithm.getName())).thenReturn(getContentSigner(privateKey, signatureAlgorithm.getName()));
        keyAccessProviderManager.signCRL(keyIdentifier, signatureAlgorithm.getName(), x509v2CRLBuilderHolder, new X500Principal("CN=" + "CN_PKI"));
    }

    @Test(expected = CRLException.class)
        public void testSignCRL_CRLServiceException() throws KeyIdentifierNotFoundException,
                KeyAccessProviderServiceException, InvalidCRLExtensionsException, SignCRLException {
        final String signatureAlgorithm = "SHA256WithRSA";
        Mockito.when(keyPairPersistenceHandler.getPrivateKey(keyIdentifier)).thenReturn(null);
        final X509v2CRLBuilderHolder x509v2CRLBuilderHolder = new X509v2CRLBuilderHolder();
        x509v2CRLBuilderHolder.setSubjectDN("CN=CN_PKI");
        Mockito.when(signerUtility.getContentSigner(keyIdentifier, signatureAlgorithm)).thenThrow(CRLException.class);
        keyAccessProviderManager.signCRL(keyIdentifier, signatureAlgorithm, x509v2CRLBuilderHolder, new X500Principal("CN=" + "CN_PKI"));
    }

    @Test
    public void testUpdateKeyPairStatus() throws KeyIdentifierNotFoundException, KeyAccessProviderServiceException, NotSupportedException {
        final KeyPairStatus keyPairStatus = KeyPairStatus.INACTIVE;
        keyAccessProviderManager.updateKeyPairStatus(keyIdentifier, keyPairStatus);
    }

    @Test(expected = NotSupportedException.class)
        public void testUpdateKeyPairStatus_KeyAccessProviderServiceException()
                throws KeyIdentifierNotFoundException, KeyAccessProviderServiceException, NotSupportedException {
        final KeyPairStatus keyPairStatus = KeyPairStatus.ACTIVE;
        keyAccessProviderManager.updateKeyPairStatus(keyIdentifier, keyPairStatus);
    }

    private List<CertificateExtensionHolder> buildCertificateExtensionholders() throws IOException {
        List<Extension> extensions = new ArrayList<Extension>();
        final Extension extension = new Extension(Extension.basicConstraints, false, new DEROctetString(new org.bouncycastle.asn1.x509.BasicConstraints(1)));
        extensions.add(extension);
        List<CertificateExtensionHolder> certificateExtensionHolders = new ArrayList<CertificateExtensionHolder>();
        for (final Extension ext : extensions) {
            if (extension != null) {
                final CertificateExtensionHolder certificateExtensionHolder = new CertificateExtensionHolder(extension.getExtnId().getId(), extension.isCritical(), extension.getExtnValue()
                        .getOctets());
                certificateExtensionHolders.add(certificateExtensionHolder);
                logger.debug("Added extension for building X509Certificate {} ", extension.getExtnId());
            }

        }
        return certificateExtensionHolders;
    }

}
