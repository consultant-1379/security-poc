/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.kaps.builder;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.kaps.certificate.exception.CSRGenerationException;
import com.ericsson.oss.itpf.security.kaps.common.BaseTest;
import com.ericsson.oss.itpf.security.kaps.common.persistence.handler.KeyPairPersistenceHandler;
import com.ericsson.oss.itpf.security.kaps.common.utils.SignerUtility;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.holder.CertificateExtensionHolder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class CSRBuilderTest extends BaseTest {

    @InjectMocks
    CSRBuilder csrBuilder;

    @Mock
    KeyPairPersistenceHandler keyPairPersistenceHandler;

    @Mock
    SignerUtility signerUtility;

    @Mock
    ContentSigner contentSigner;

    @Mock
    ASN1Set attributes;

    @Mock
    ASN1Encoding asn1Encoding;

    @Mock
    Signature signature;

    private X500Name subject;
    private Algorithm signatureAlgorithm;
    private KeyIdentifier keyIdentifier;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private CertificationRequestInfo certificationRequestInfo;
    List<CertificateExtensionHolder> CertificateExtensionHolder = null;

    @Before
    public void setUp() throws NoSuchAlgorithmException, IOException {

        CertificateExtensionHolder = buildCertificateExtensionholders();
        subject = new X500Name("CN=enmSecurity, O=Ericsson");
        signatureAlgorithm = prepareSignatureAlgorithm();
        keyIdentifier = new KeyIdentifier();
        keyIdentifier.setId("1");
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        // certificationRequestInfo = new CertificationRequestInfo(subject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()), attributes);
    }

    /**
     * Test method for building of {@link PKCS10CertificationRequest}
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     */
    @Test
    public void testGeneratePKCS10Request() throws KeyIdentifierNotFoundException, KeyAccessProviderServiceException {

        try {
            Mockito.when(keyPairPersistenceHandler.getPublicKey(keyIdentifier)).thenReturn(publicKey);
            Mockito.when(signerUtility.getContentSigner(keyIdentifier, signatureAlgorithm.getName())).thenReturn(getContentSigner(privateKey, signatureAlgorithm.getName()));
            final PKCS10CertificationRequest certificationRequest = csrBuilder.buildPKCS10CertificationRequest(keyIdentifier, signatureAlgorithm.getName(), subject, null);
            assertNotNull(certificationRequest);
            assertEquals(certificationRequest.getSubject(), subject);
        } catch (CSRGenerationException e) {

        }

    }

    @Ignore
    @Test(expected = CSRGenerationException.class)
        public void testGeneratePKCS10Request_CSRGenerationException()
                throws KeyIdentifierNotFoundException, KeyAccessProviderServiceException, CSRGenerationException {
        Mockito.when(keyPairPersistenceHandler.getPublicKey(keyIdentifier)).thenReturn(publicKey);
        Mockito.when(keyPairPersistenceHandler.getPrivateKey(keyIdentifier)).thenReturn(privateKey);
        Mockito.when(signerUtility.getContentSigner(keyIdentifier, signatureAlgorithm.getName())).thenThrow(new CSRGenerationException("CSR signature generation failed."));
        csrBuilder.buildPKCS10CertificationRequest(keyIdentifier, "SHA1WITHRSADSA", subject, null);
    }

    @Test
        public void testBuildPKCS10CertificationRequest()
                throws KeyIdentifierNotFoundException, KeyAccessProviderServiceException, CSRGenerationException {
        Mockito.when(keyPairPersistenceHandler.getPublicKey(keyIdentifier)).thenReturn(publicKey);
        Mockito.when(keyPairPersistenceHandler.getPrivateKey(keyIdentifier)).thenReturn(privateKey);
        Mockito.when(signerUtility.getContentSigner(keyIdentifier, signatureAlgorithm.getName())).thenReturn(getContentSigner(privateKey, signatureAlgorithm.getName()));
        csrBuilder.buildPKCS10CertificationRequest(keyIdentifier, signatureAlgorithm.getName(), subject, CertificateExtensionHolder);
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
