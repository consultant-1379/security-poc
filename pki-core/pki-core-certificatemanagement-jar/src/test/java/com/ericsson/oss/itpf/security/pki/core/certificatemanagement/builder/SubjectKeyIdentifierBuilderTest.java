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

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateExtensionsException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidSubjectKeyIdentifierException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException;

@RunWith(MockitoJUnitRunner.class)
public class SubjectKeyIdentifierBuilderTest extends BaseTest {

    @InjectMocks
    private SubjectKeyIdentifierBuilder subjectKeyIdentifierBuilder;

    @Mock
    private JcaPKCS10CertificationRequest csr;

    private SubjectKeyIdentifier subjectKeyIdentifier;
    private KeyPair keyPair;
    private Extension subjectKeyIdentifierActual;
    private KeyIdentifier keyIdentifier;

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        keyIdentifier = new KeyIdentifier();
        subjectKeyIdentifier = new SubjectKeyIdentifier();
        subjectKeyIdentifier.setCritical(true);

        final Algorithm keyGenerationAlgorithm = prepareKeyGenerationAlgorithm();
        keyPair = generateKeyPair(keyGenerationAlgorithm.getName(), keyGenerationAlgorithm.getKeySize());
    }

    /**
     * Method to test building of {@link SubjectKeyIdentifier} extension.
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testBuildSubjectKeyIdentifierWithType1() throws InvalidKeyException, NoSuchAlgorithmException {

        final Algorithm keyIdentifierAlgorithm = prepareKeyIdentifierAlgorithm(Constants.KEYIDENTIFIER_TYPE1);
        keyIdentifier.setAlgorithm(keyIdentifierAlgorithm);
        subjectKeyIdentifier.setKeyIdentifier(keyIdentifier);
        Mockito.when(csr.getPublicKey()).thenReturn(keyPair.getPublic());

        subjectKeyIdentifierActual = subjectKeyIdentifierBuilder.buildSubjectKeyIdentifier(subjectKeyIdentifier, csr.getPublicKey());

        final DEROctetString subjectKeyIdentifierExpected = buildSubjectKeyIdentifier(csr, Constants.KEYIDENTIFIER_TYPE1);

        assertExtensionValue(subjectKeyIdentifierExpected, subjectKeyIdentifierActual);
        assertEquals(Extension.subjectKeyIdentifier, subjectKeyIdentifierActual.getExtnId());
    }

    /**
     * Method to test building of {@link SubjectKeyIdentifier} extension.
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testBuildSubjectKeyIdentifierWithType2() throws InvalidKeyException, NoSuchAlgorithmException {

        final Algorithm keyIdentifierAlgorithm = prepareKeyIdentifierAlgorithm(Constants.KEYIDENTIFIER_TYPE2);
        keyIdentifier.setAlgorithm(keyIdentifierAlgorithm);
        subjectKeyIdentifier.setKeyIdentifier(keyIdentifier);
        Mockito.when(csr.getPublicKey()).thenReturn(keyPair.getPublic());

        subjectKeyIdentifierActual = subjectKeyIdentifierBuilder.buildSubjectKeyIdentifier(subjectKeyIdentifier, keyPair.getPublic());

        final DEROctetString subjectKeyIdentifierExpected = buildSubjectKeyIdentifier(csr, Constants.KEYIDENTIFIER_TYPE2);

        assertExtensionValue(subjectKeyIdentifierExpected, subjectKeyIdentifierActual);
        assertEquals(Extension.subjectKeyIdentifier, subjectKeyIdentifierActual.getExtnId());
    }

    /**
     * Method to test building of {@link SubjectKeyIdentifier} extension when InvalidKeyException occurs.
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testBuildSubjectKeyIdentifier_InvalidKeyException() throws NoSuchAlgorithmException, InvalidKeyException {

        final Algorithm keyIdentifierAlgorithm = prepareKeyIdentifierAlgorithm(Constants.KEYIDENTIFIER_TYPE2);
        keyIdentifier.setAlgorithm(keyIdentifierAlgorithm);
        subjectKeyIdentifier.setKeyIdentifier(keyIdentifier);
        final JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = Mockito.mock(JcaPKCS10CertificationRequest.class);

        Mockito.doThrow(new InvalidKeyException(ErrorMessages.INVALID_KEY_IN_CSR)).when(jcaPKCS10CertificationRequest).getPublicKey();

        try {
            subjectKeyIdentifierBuilder.buildSubjectKeyIdentifier(subjectKeyIdentifier, keyPair.getPublic());

        } catch (InvalidCertificateRequestException invalidCSRException) {
            assertTrue(invalidCSRException.getMessage().contains(ErrorMessages.INVALID_KEY_IN_CSR));
        }
    }

    /**
     * Method to test building of {@link SubjectKeyIdentifier} extension.
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void testBuildSubjectKeyIdentifier_NoSuchAlgorithmException() throws InvalidKeyException, NoSuchAlgorithmException {

        final Algorithm keyIdentifierAlgorithm = prepareKeyIdentifierAlgorithm(Constants.KEYIDENTIFIER_TYPE2);
        keyIdentifier.setAlgorithm(keyIdentifierAlgorithm);
        subjectKeyIdentifier.setKeyIdentifier(keyIdentifier);
        final JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = Mockito.mock(JcaPKCS10CertificationRequest.class);

        Mockito.doThrow(new NoSuchAlgorithmException(ErrorMessages.ALGORITHM_TO_BUILD_KEY_IDENTIFIER_IS_INVALID)).when(jcaPKCS10CertificationRequest).getPublicKey();

        try {
            subjectKeyIdentifierBuilder.buildSubjectKeyIdentifier(subjectKeyIdentifier, keyPair.getPublic());

        } catch (InvalidCertificateExtensionsException invalidCertificateExtensionsException) {
            assertTrue(invalidCertificateExtensionsException.getMessage().contains(ErrorMessages.ALGORITHM_TO_BUILD_KEY_IDENTIFIER_IS_INVALID));
        }
    }

    private DEROctetString buildSubjectKeyIdentifier(final JcaPKCS10CertificationRequest csr, final String subjectKeyIdentifier) {
        try {

            final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            org.bouncycastle.asn1.x509.SubjectKeyIdentifier subjectKeyIdentifierExtension = null;

            if (subjectKeyIdentifier.equals(Constants.KEYIDENTIFIER_TYPE1)) {
                subjectKeyIdentifierExtension = extUtils.createSubjectKeyIdentifier(csr.getPublicKey());
            } else if (subjectKeyIdentifier.equals(Constants.KEYIDENTIFIER_TYPE2)) {
                subjectKeyIdentifierExtension = extUtils.createTruncatedSubjectKeyIdentifier(csr.getPublicKey());
            }

            return new DEROctetString(subjectKeyIdentifierExtension);

        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(ErrorMessages.ALGORITHM_TO_BUILD_KEY_IDENTIFIER_IS_INVALID, noSuchAlgorithmException);
            throw new InvalidSubjectKeyIdentifierException(ErrorMessages.ALGORITHM_TO_BUILD_KEY_IDENTIFIER_IS_INVALID);
        } catch (InvalidKeyException invalidKeyException) {
            logger.error(ErrorMessages.INVALID_KEY_IN_CSR, invalidKeyException);
            throw new InvalidCertificateRequestException(ErrorMessages.INVALID_KEY_IN_CSR);
        } catch (IOException ioException) {
            logger.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, ioException);
            throw new InvalidSubjectKeyIdentifierException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
        }
    }
}
