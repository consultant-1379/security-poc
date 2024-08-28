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
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.kaps.api.KeyAccessProviderService;
import com.ericsson.oss.itpf.security.kaps.certificate.exception.CSRGenerationException;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class ExtensionBuilderTest extends BaseTest {

    @InjectMocks
    ExtensionBuilder extensionBuilder;

    @Mock
    AuthorityInformationAccessBuilder authorityInformationAccessBuilder;

    @Mock
    AuthorityKeyIdentifierBuilder authorityKeyIdentifierBuilder;

    @Mock
    BasicConstraintsBuilder basicConstraintsBuilder;

    @Mock
    CRLDistributionPointsBuilder cRLDistributionPointsBuilder;

    @Mock
    ExtendedKeyUsageBuilder extendedKeyUsageBuilder;

    @Mock
    KeyUsageBuilder keyUsageBuilder;

    @Mock
    SubjectAltNameBuilder subjectAltNameBuilder;

    @Mock
    SubjectKeyIdentifierBuilder subjectKeyIdentifierBuilder;

    @Mock
    KeyAccessProviderService keyAccessProviderServiceMock;

    private CertificateGenerationInfo certificateGenerationInfo;
    private KeyPair subjectkeyPair;
    private CertificateAuthority certificateAuthority;
    private CertificateExtensions certificateExtensions;
    private List<CertificateExtension> certificateExtensionsList;
    private com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier keyIdentifier;

    /**
     * Prepares initial data.
     * 
     * @throws NoSuchAlgorithmException
     *             {@link NoSuchAlgorithmException}
     */
    @Before
    public void setUp() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());

        certificateExtensionsList = new ArrayList<CertificateExtension>();
        certificateExtensions = new CertificateExtensions();
        certificateGenerationInfo = new CertificateGenerationInfo();

        final Algorithm keyGenerationAlgorithm = prepareKeyGenerationAlgorithm();
        final Algorithm signatureAlgorithm = prepareSignatureAlgorithm();
        certificateAuthority = prepareCAData(true);

        certificateGenerationInfo.setCAEntityInfo(certificateAuthority);
        certificateGenerationInfo.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        certificateGenerationInfo.setSignatureAlgorithm(signatureAlgorithm);

        subjectkeyPair = generateKeyPair(keyGenerationAlgorithm.getName(), keyGenerationAlgorithm.getKeySize());
    }

    /**
     * Method to test building of {@link CertificateExtensions}
     *
     * @throws NoSuchAlgorithmException
     *             {@link NoSuchAlgorithmException}
     * @throws InvalidKeyException
     *             {@link InvalidKeyException}
     * @throws IOException
     *             {@link IOException}
     * @throws CertificateException
     *             {@link CertificateException}
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     * @throws CSRGenerationException
     */
    @Test
    public void testBuildCertificateExtensions() throws CertificateException, CSRGenerationException, InvalidKeyException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException, NoSuchAlgorithmException {

        final String subject = certificateGenerationInfo.getCAEntityInfo().getSubject().toASN1String();

        generateExtensions();
        final PKCS10CertificationRequestHolder pkcs10CertificationRequest = keyAccessProviderServiceMock.generateCSR(keyIdentifier, certificateGenerationInfo.getSignatureAlgorithm().getName(),
                subject, null);

        final List<Extension> buildCertificateExtensions = extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, subjectkeyPair.getPublic());

        assertNotNull(buildCertificateExtensions);
        assertEquals(certificateGenerationInfo.getCertificateExtensions().getCertificateExtensions().size(), buildCertificateExtensions.size());
    }

    /**
     * Method to test occurrence of {@link InvalidCSRException}
     * 
     * @throws NoSuchAlgorithmException
     *             {@link NoSuchAlgorithmException}
     * @throws InvalidKeyException
     *             {@link InvalidKeyException}
     * @throws IOException
     *             {@link IOException}
     * @throws CertificateException
     *             {@link CertificateException}
     */
    @Test
    public void testBuildCertificateExtensions_InvalidCSRException() throws NoSuchAlgorithmException, InvalidKeyException, IOException, CertificateException {
        generateExtensions();

        final PKCS10CertificationRequest certificationRequest = Mockito.mock(PKCS10CertificationRequest.class);

        Mockito.doThrow(new IOException(ErrorMessages.INVALID_CSR_ENCODING)).when(certificationRequest).getEncoded();

        try {
            extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, subjectkeyPair.getPublic());

        } catch (InvalidCertificateRequestException invalidCSRException) {
            assertTrue(invalidCSRException.getMessage().contains(ErrorMessages.INVALID_CSR_ENCODING));
        }
    }

    private BasicConstraints prepareBasicConstraints() {
        final BasicConstraints basicConstraints = new BasicConstraints();
        basicConstraints.setCritical(true);
        basicConstraints.setIsCA(true);
        basicConstraints.setPathLenConstraint(3);
        return basicConstraints;
    }

    private ExtendedKeyUsage prepareExtededKeyUsage() {
        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();

        final List<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.ANY_EXTENDED_KEY_USAGE);
        keyPurposeIds.add(KeyPurposeId.ID_KP_CLIENT_AUTH);
        keyPurposeIds.add(KeyPurposeId.ID_KP_CODE_SIGNING);
        keyPurposeIds.add(KeyPurposeId.ID_KP_EMAIL_PROTECTION);
        keyPurposeIds.add(KeyPurposeId.ID_KP_OCSP_SIGNING);
        keyPurposeIds.add(KeyPurposeId.ID_KP_SERVER_AUTH);
        keyPurposeIds.add(KeyPurposeId.ID_KP_TIME_STAMPING);

        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIds);
        return extendedKeyUsage;
    }

    private KeyUsage prepareKeyUsage() {
        final KeyUsage keyUsage = new KeyUsage();
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();

        keyUsageTypes.add(KeyUsageType.CRL_SIGN);
        keyUsageTypes.add(KeyUsageType.KEY_CERT_SIGN);
        keyUsageTypes.add(KeyUsageType.DIGITAL_SIGNATURE);
        keyUsageTypes.add(KeyUsageType.NON_REPUDIATION);

        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        return keyUsage;
    }

    private SubjectKeyIdentifier prepareSubjectKeyIdentifier() {
        final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
        final KeyIdentifier keyIdentifier = new KeyIdentifier();
        keyIdentifier.setAlgorithm(prepareKeyIdentifierAlgorithm(Constants.KEYIDENTIFIER_TYPE2));
        subjectKeyIdentifier.setKeyIdentifier(keyIdentifier);
        subjectKeyIdentifier.setCritical(true);

        return subjectKeyIdentifier;
    }

    private AuthorityKeyIdentifier prepareAuthorityKeyIdentifier() {
        final AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
        final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
        final KeyIdentifier keyIdentifier = new KeyIdentifier();
        keyIdentifier.setAlgorithm(prepareKeyIdentifierAlgorithm(Constants.KEYIDENTIFIER_TYPE2));
        authorityKeyIdentifier.setCritical(true);
        authorityKeyIdentifier.setSubjectkeyIdentifier(subjectKeyIdentifier);

        return authorityKeyIdentifier;
    }

    private CRLDistributionPoints prepareCRLDistributionPoints() {
        final CRLDistributionPoints cRLDistributionPoints = new CRLDistributionPoints();
        final List<DistributionPoint> distributionPoints = new ArrayList<DistributionPoint>();
        final DistributionPoint distributionPoint = new DistributionPoint();
        final DistributionPointName distributionPointName = new DistributionPointName();

        final List<String> fullNames = new ArrayList<String>();
        fullNames.add("http://www.crl.com");
        distributionPointName.setFullName(fullNames);
        distributionPoint.setDistributionPointName(distributionPointName);
        distributionPoints.add(distributionPoint);
        cRLDistributionPoints.setDistributionPoints(distributionPoints);

        cRLDistributionPoints.setCritical(false);

        return cRLDistributionPoints;
    }

    private AuthorityInformationAccess prepareAuthorityInformationAccess() {
        final AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess();
        final AccessDescription accessDescriptionOCSP = new AccessDescription();
        final AccessDescription accessDescriptionCAIssuer = new AccessDescription();
        final List<AccessDescription> accessDescriptionList = new ArrayList<AccessDescription>();

        accessDescriptionOCSP.setAccessMethod(AccessMethod.OCSP);
        accessDescriptionOCSP.setAccessLocation("http://www.ocsp.com");
        accessDescriptionList.add(accessDescriptionOCSP);
        accessDescriptionCAIssuer.setAccessMethod(AccessMethod.CA_ISSUER);
        accessDescriptionCAIssuer.setAccessLocation("http://www.caIssuer.com");
        accessDescriptionList.add(accessDescriptionCAIssuer);

        authorityInformationAccess.setCritical(true);
        authorityInformationAccess.setAccessDescriptions(accessDescriptionList);

        return authorityInformationAccess;
    }

    private void generateExtensions() {
        final AuthorityInformationAccess authorityInformationAccess = prepareAuthorityInformationAccess();
        final BasicConstraints basicConstraints = prepareBasicConstraints();
        final ExtendedKeyUsage extendedKeyUsage = prepareExtededKeyUsage();
        final KeyUsage keyUsage = prepareKeyUsage();
        final SubjectKeyIdentifier subjectKeyIdentifier = prepareSubjectKeyIdentifier();
        final AuthorityKeyIdentifier authorityKeyIdentifier = prepareAuthorityKeyIdentifier();
        final CRLDistributionPoints crlDistributionPoints = prepareCRLDistributionPoints();

        certificateExtensionsList.add(subjectKeyIdentifier);
        certificateExtensionsList.add(authorityKeyIdentifier);
        certificateExtensionsList.add(authorityInformationAccess);
        certificateExtensionsList.add(basicConstraints);
        certificateExtensionsList.add(extendedKeyUsage);
        certificateExtensionsList.add(keyUsage);
        certificateExtensionsList.add(crlDistributionPoints);

        certificateExtensions.setCertificateExtensions(certificateExtensionsList);
        certificateGenerationInfo.setCertificateExtensions(certificateExtensions);
    }
}
