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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifierType;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.utils.CertificateGenerationInfoParser;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateExtensionsException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class AuthorityKeyIdentifierBuilderTest extends BaseTest {

    @InjectMocks
    private AuthorityKeyIdentifierBuilder authorityKeyIdentifierBuilder;

    @Mock
    private JcaPKCS10CertificationRequest csr;

    @Mock
    private X509Certificate certificate;

    @Mock
    private CertificateAuthorityData certificateAuthorityData;

    @Mock
    private CertificateGenerationInfoParser certificateGenerationInfoParser;

    private static CertificateGenerationInfo certificateGenerationInfo;
    private CertificateAuthority certificateAuthority;
    private AuthorityKeyIdentifier authorityKeyIdentifier;
    private KeyPair keyPair;
    private Extension authorityKeyIdentitfierExtension;
    private CertificateData certificateData;
    private Set<CertificateData> certificates;

    /**
     * Prepares initial data.
     * 
     * @throws NoSuchAlgorithmException
     * @throws CertificateEncodingException
     * @throws CertificateException
     * @throws IOException
     */
    @Before
    public void setUp() throws NoSuchAlgorithmException, CertificateEncodingException, CertificateException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        certificates = new HashSet<CertificateData>();
        certificateData = new CertificateData();

        authorityKeyIdentifier = new AuthorityKeyIdentifier();
        certificateGenerationInfo = new CertificateGenerationInfo();

        final Algorithm keyGenerationAlgorithm = prepareKeyGenerationAlgorithm();

        keyPair = generateKeyPair(keyGenerationAlgorithm.getName(), keyGenerationAlgorithm.getKeySize());

        certificateData.setStatus(CertificateStatus.ACTIVE);
        certificateData.setCertificate(getCertificate("src/test/resources/MyRoot.crt").getEncoded());
        certificates.add(certificateData);
    }

    /**
     * Method to set data for RootCA to generate {@link AuthorityKeyIdentifier} extension.
     * 
     * @param authorityKeyIdentifierType
     *            type that specifies way to generate authority key identifier.
     */
    public void setDataForRootCA(final AuthorityKeyIdentifierType authorityKeyIdentifierType) {

        final boolean isCritical = true;
        certificateAuthority = prepareCAData(true);
        certificateGenerationInfo.setCAEntityInfo(certificateAuthority);

        if (authorityKeyIdentifierType == AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER) {
            authorityKeyIdentifier.setType(authorityKeyIdentifierType);
        } else if (authorityKeyIdentifierType == AuthorityKeyIdentifierType.ISSUER_DN_SERIAL_NUMBER) {
            authorityKeyIdentifier.setType(authorityKeyIdentifierType);
        }
        certificateGenerationInfo.setIssuerCA(null);
        authorityKeyIdentifier.setCritical(isCritical);

    }

    /**
     * Method to set data for SubCA to generate {@link AuthorityKeyIdentifier} extension.
     */
    public void setDataForSubCA(final AuthorityKeyIdentifierType authorityKeyIdentifierType) {
        final boolean isCritical = true;
        certificateAuthority = prepareCAData(false);

        if (authorityKeyIdentifierType == AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER) {
            authorityKeyIdentifier.setType(authorityKeyIdentifierType);
        } else if (authorityKeyIdentifierType == AuthorityKeyIdentifierType.ISSUER_DN_SERIAL_NUMBER) {
            authorityKeyIdentifier.setType(authorityKeyIdentifierType);
        }
        certificateGenerationInfo.setIssuerCA(prepareCAData(true));
        certificateGenerationInfo.setCAEntityInfo(certificateAuthority);
        authorityKeyIdentifier.setCritical(isCritical);
    }

    /**
     * Method to test building of {@link AuthorityKeyIdentifier} extension by keyIdentifier.
     * 
     * @throws InvalidKeyException
     *             {@link InvalidKeyException}
     * @throws NoSuchAlgorithmException
     *             {@link NoSuchAlgorithmException}
     * @throws CertificateException
     *             {@link CertificateException}
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildAuthorityIdentifierForRootCAByKeyIdentifier() throws InvalidKeyException, NoSuchAlgorithmException, CertificateException, IOException {
        final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        setDataForRootCA(AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER);

        Mockito.when(csr.getPublicKey()).thenReturn(keyPair.getPublic());

        final DEROctetString authorityKeyIdentifierExtensionExpexted = new DEROctetString(extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));

        authorityKeyIdentitfierExtension = authorityKeyIdentifierBuilder.buildAuthorityIdentifier(certificateGenerationInfo, authorityKeyIdentifier, keyPair.getPublic(), null);

        assertNotNull(authorityKeyIdentitfierExtension);
        assertEquals(Extension.authorityKeyIdentifier, authorityKeyIdentitfierExtension.getExtnId());
        assertTrue(authorityKeyIdentitfierExtension.isCritical());
        assertEquals(authorityKeyIdentifierExtensionExpexted, authorityKeyIdentitfierExtension.getExtnValue());
    }

    /**
     * Method to test occurrence of {@link InvalidCSRException} when buildAuthorityKeyIdentifier method is called.
     * 
     * @throws InvalidKeyException
     *             {@link InvalidKeyException}
     * @throws NoSuchAlgorithmException
     *             {@link NoSuchAlgorithmException}
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildAuthorityIdentifier_InvalidKeyException() throws InvalidKeyException, NoSuchAlgorithmException, IOException {

        setDataForRootCA(AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER);

        final JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = Mockito.mock(JcaPKCS10CertificationRequest.class);

        Mockito.doThrow(new InvalidKeyException(ErrorMessages.INVALID_KEY_IN_CSR)).when(jcaPKCS10CertificationRequest).getPublicKey();

        try {
            authorityKeyIdentifierBuilder.buildAuthorityIdentifier(certificateGenerationInfo, authorityKeyIdentifier, keyPair.getPublic(), null);
        } catch (InvalidCertificateRequestException invalidCSRException) {
            assertTrue(invalidCSRException.getMessage().contains(ErrorMessages.INVALID_KEY_IN_CSR));
        }
    }

    /**
     * Method to test occurrence of {@link InvalidCSRException} when buildAuthorityKeyIdentifier method is called.
     * 
     * @throws InvalidKeyException
     *             {@link InvalidKeyException}
     * @throws NoSuchAlgorithmException
     *             {@link NoSuchAlgorithmException}
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testBuildAuthorityIdentifier_NoSuchAlgorithmException() throws InvalidKeyException, NoSuchAlgorithmException, IOException {

        setDataForRootCA(AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER);

        final JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = Mockito.mock(JcaPKCS10CertificationRequest.class);

        Mockito.doThrow(new NoSuchAlgorithmException(ErrorMessages.ALGORITHM_TO_BUILD_KEY_IDENTIFIER_IS_INVALID)).when(jcaPKCS10CertificationRequest).getPublicKey();

        try {
            authorityKeyIdentifierBuilder.buildAuthorityIdentifier(certificateGenerationInfo, authorityKeyIdentifier, keyPair.getPublic(), null);
        } catch (InvalidCertificateExtensionsException invalidCertificateExtensionsException) {
            assertTrue(invalidCertificateExtensionsException.getMessage().contains(ErrorMessages.ALGORITHM_TO_BUILD_KEY_IDENTIFIER_IS_INVALID));
        }
    }

    /**
     * Method to test building of {@link AuthorityKeyIdentifier} extension by Issuer name and serial number.
     * 
     * @throws InvalidKeyException
     *             {@link InvalidKeyException}
     * @throws NoSuchAlgorithmException
     *             {@link NoSuchAlgorithmException}
     * @throws CertificateException
     *             {@link CertificateException}
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    @Ignore
    public void testBuildAuthorityIdentifierByIssuerNameAndSerialNumber() throws InvalidKeyException, NoSuchAlgorithmException, CertificateException, IOException {

        setDataForRootCA(AuthorityKeyIdentifierType.ISSUER_DN_SERIAL_NUMBER);

        certificateAuthorityData.setCertificateDatas(certificates);

        Mockito.when(certGenInfoParser.getIssuerDNFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(certificateGenerationInfo.getCAEntityInfo().getSubject().toASN1String());
        Mockito.when(persistenceHelper.getCA(SUB_CA)).thenReturn(certificateAuthorityData);

        authorityKeyIdentitfierExtension = authorityKeyIdentifierBuilder.buildAuthorityIdentifier(certificateGenerationInfo, authorityKeyIdentifier, keyPair.getPublic(), null);

        assertNotNull(authorityKeyIdentitfierExtension);
        assertEquals(Extension.authorityKeyIdentifier, authorityKeyIdentitfierExtension.getExtnId());
        assertTrue(authorityKeyIdentitfierExtension.isCritical());
    }

    /**
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testBuildAuthorityIdentifierForSubCA() throws InvalidKeyException, NoSuchAlgorithmException, CertificateException, IOException {
        final String issuerCAName = "ENM_RootCA";
        setDataForSubCA(AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER);

        Mockito.when(persistenceHelper.getCA(issuerCAName)).thenReturn(certificateAuthorityData);
        Mockito.when(certificateAuthorityData.getCertificateDatas()).thenReturn(certificates);

        authorityKeyIdentitfierExtension = authorityKeyIdentifierBuilder.buildAuthorityIdentifier(certificateGenerationInfo, authorityKeyIdentifier, keyPair.getPublic(), null);

        final DEROctetString authorityKeyIdentifierExpected = getAuthorityKeyIdentifier(certificateGenerationInfo.getIssuerCA().getName());

        assertNotNull(authorityKeyIdentitfierExtension);
        assertEquals(Extension.authorityKeyIdentifier, authorityKeyIdentitfierExtension.getExtnId());
        assertTrue(authorityKeyIdentitfierExtension.isCritical());
        assertEquals(authorityKeyIdentifierExpected, authorityKeyIdentitfierExtension.getExtnValue());
    }

    private DEROctetString getAuthorityKeyIdentifier(final String cAName) throws CertificateException, IOException, NoSuchAlgorithmException {
        DEROctetString authorityKeyIdentifier = null;
        final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        final CertificateAuthorityData issuerCA = persistenceHelper.getCA(cAName);
        final Set<CertificateData> certificates = issuerCA.getCertificateDatas();
        for (final CertificateData certData : certificates) {
            if (certData.getStatus() == CertificateStatus.ACTIVE) {

                final X509CertificateHolder certificateHolder = new X509CertificateHolder(certData.getCertificate());
                final X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateHolder);
                authorityKeyIdentifier = new DEROctetString(extUtils.createAuthorityKeyIdentifier(certificate.getPublicKey()));
            }
        }
        return authorityKeyIdentifier;
    }

}
