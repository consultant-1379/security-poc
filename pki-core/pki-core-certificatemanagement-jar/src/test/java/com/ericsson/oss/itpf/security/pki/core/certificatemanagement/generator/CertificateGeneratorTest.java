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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.generator;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.security.auth.x500.X500Principal;
import javax.xml.datatype.*;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.kaps.api.KeyAccessProviderService;
import com.ericsson.oss.itpf.security.kaps.certificate.exception.CertificateSignatureException;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.holder.X509v3CertificateBuilderHolder;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder.ExtensionBuilder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.eserviceproxy.KeyAccessProviderServiceProxy;
import com.ericsson.oss.itpf.security.pki.core.common.utils.DateUtil;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.InvalidCertificateRequestException;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class CertificateGeneratorTest extends BaseTest {

    @InjectMocks
    private CertificateGenerator certificateGenerator;

    @Mock
    private SerialNumberGenerator serialNumberGenerator;

    @Mock
    private DateUtil dateUtil;

    @Mock
    KeyAccessProviderService keyAccessProviderService;

    @Mock
    ExtensionBuilder extensionBuilder;

    @Mock
    KeyAccessProviderServiceProxy keyAccessProviderServiceProxy;

    private CertificateGenerationInfo certificateInfo;
    private String issuerDN;
    private String subjectDN;
    private KeyPair keyPair;
    private List<Extension> extensions;
    private String serialNumber;
    private Date notBefore;
    private Date notAfter;
    private Duration duration;
    private CertificateAuthority certificateAuthority;
    private PKCS10CertificationRequest certificateRequest;
    private PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder;
    private KeyIdentifier keyIdentifier;
    private PublicKey publicKey;
    private X509v3CertificateBuilder x509v3CertificateBuilder;
    private X509Certificate x509Certificate;
    private String signatureAlgorithm;
    private static Certificate certificate;

    /**
     * Prepares initial data.
     * 
     * @throws NoSuchAlgorithmException
     * @throws DatatypeConfigurationException
     * @throws IOException
     * @throws InvalidKeyException
     */
    @Before
    public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        final Algorithm keyGenerationAlgorithm = prepareKeyGenerationAlgorithm();
        final String DURATION = "P2Y8M24D";
        duration = DatatypeFactory.newInstance().newDuration(DURATION);
        notBefore = new Date(2015, 03, 23);
        notAfter = addDurationToDate(notBefore, duration);

        keyPair = generateKeyPair(keyGenerationAlgorithm.getName(), keyGenerationAlgorithm.getKeySize());
        publicKey = keyPair.getPublic();

        keyIdentifier = new KeyIdentifier();

        extensions = new ArrayList<Extension>();
        final Extension extension = new Extension(Extension.basicConstraints, false, new DEROctetString(new org.bouncycastle.asn1.x509.BasicConstraints(1)));
        extensions.add(extension);

        GeneralName[] subjectAltName = new GeneralName[2];
        subjectAltName[0] = new GeneralName(GeneralName.dNSName, "abc.com");
        subjectAltName[1] = new GeneralName(GeneralName.directoryName, "CN=dir");

        certificateRequest = generatePKCS10Request(Arrays.asList(subjectAltName));
        pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(certificateRequest);
        x509Certificate = getCertificate("src/test/resources/MyRoot.crt");
        Mockito.when(keyAccessProviderServiceProxy.getKeyAccessProviderService()).thenReturn(keyAccessProviderService);
    }

    /**
     * Method to test generation of {@link X509Certificate} for CA.
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     * @throws com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException
     * @throws CertificateSignatureException
     */
    @Test
    public void testGenerateCertificateForCA() throws InvalidKeyException, NoSuchAlgorithmException, IOException, CertificateSignatureException, com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException, KeyIdentifierNotFoundException, KeyAccessProviderServiceException {
        prepareCAData();

        Mockito.when(certGenInfoParser.getSubjectDNFromCertGenerationInfo(certificateInfo)).thenReturn(subjectDN);
        Mockito.when(certGenInfoParser.getIssuerDNFromCertGenerationInfo(certificateInfo)).thenReturn(issuerDN);
        Mockito.when(serialNumberGenerator.generateSerialNumber()).thenReturn(serialNumber);

        Mockito.when(dateUtil.getCurrentDate()).thenReturn(notBefore);
        Mockito.when(dateUtil.addDurationToDate(dateUtil.getCurrentDate(), certificateInfo.getValidity())).thenReturn(notAfter);
        Mockito.when(keyAccessProviderService.signCertificate(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.any(X509v3CertificateBuilderHolder.class), Mockito.any(X500Principal.class))).thenReturn(x509Certificate);

        final X509Certificate certificate = certificateGenerator.generateCertificate(certificateInfo, keyIdentifier, keyPair.getPublic(), extensions);

        doAssertionsForGenerateCertificate(certificate);
    }

    /**
     * Method to test generation of {@link X509Certificate} for CA.
     * 
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws OperatorCreationException
     */
    @Test
    public void testGenerateCertificate_IOException() throws InvalidKeyException, NoSuchAlgorithmException, IOException, OperatorCreationException {
        prepareCAData();

        final PKCS10CertificationRequest certificationRequest = Mockito.mock(PKCS10CertificationRequest.class);

        Mockito.doThrow(new IOException(ErrorMessages.INVALID_CSR_ENCODING)).when(certificationRequest).getEncoded();

        Mockito.when(serialNumberGenerator.generateSerialNumber()).thenReturn(serialNumber);

        Mockito.when(dateUtil.getCurrentDate()).thenReturn(notBefore);

        Mockito.when(dateUtil.addDurationToDate(dateUtil.getCurrentDate(), certificateInfo.getValidity())).thenReturn(notAfter);

        Mockito.when(certGenInfoParser.getIssuerDNFromCertGenerationInfo(certificateInfo)).thenReturn(issuerDN);

        Mockito.when(certGenInfoParser.getSubjectDNFromCertGenerationInfo(certificateInfo)).thenReturn(subjectDN);

        try {

            certificateGenerator.generateCertificate(certificateInfo, keyIdentifier, keyPair.getPublic(), extensions);

        } catch (InvalidCertificateRequestException invalidCSRException) {
            assertTrue(invalidCSRException.getMessage().contains(ErrorMessages.INVALID_CSR_ENCODING));
        }
    }

    /**
     * Method to test generation of {@link X509Certificate} for Entity.
     *
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     * @throws com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException
     * @throws CertificateSignatureException
     */
    @Test
    public void testGenerateCertificateForEntity() throws CertificateSignatureException, InvalidKeyException, com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException, NoSuchAlgorithmException {
        prepareEntityData();

        Mockito.when(certGenInfoParser.getSubjectDNFromCertGenerationInfo(certificateInfo)).thenReturn(subjectDN);
        Mockito.when(certGenInfoParser.getIssuerDNFromCertGenerationInfo(certificateInfo)).thenReturn(issuerDN);
        Mockito.when(serialNumberGenerator.generateSerialNumber()).thenReturn(serialNumber);

        Mockito.when(dateUtil.getCurrentDate()).thenReturn(notBefore);
        Mockito.when(dateUtil.addDurationToDate(dateUtil.getCurrentDate(), certificateInfo.getValidity())).thenReturn(notAfter);
        Mockito.when(keyAccessProviderService.signCertificate(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.any(X509v3CertificateBuilderHolder.class), Mockito.any(X500Principal.class))).thenReturn(x509Certificate);

        final X509Certificate certificate = certificateGenerator.generateCertificate(certificateInfo, keyIdentifier, keyPair.getPublic(), extensions);

        doAssertionsForGenerateCertificate(certificate);
    }

    /**
     * Method to test generation of {@link X509Certificate} for CA.
     *
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     * @throws com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException
     * @throws CertificateSignatureException
     */
    @Test(expected = InvalidCertificateExtensionsException.class)
    public void testGenerateCertificateForCAException() throws CertificateSignatureException, com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {
        prepareCAData();

        Mockito.when(certGenInfoParser.getSubjectDNFromCertGenerationInfo(certificateInfo)).thenReturn(subjectDN);
        Mockito.when(certGenInfoParser.getIssuerDNFromCertGenerationInfo(certificateInfo)).thenReturn(issuerDN);
        Mockito.when(serialNumberGenerator.generateSerialNumber()).thenReturn(serialNumber);

        Mockito.when(dateUtil.getCurrentDate()).thenReturn(notBefore);
        Mockito.when(dateUtil.addDurationToDate(dateUtil.getCurrentDate(), certificateInfo.getValidity())).thenReturn(notAfter);

        Mockito.when(keyAccessProviderService.signCertificate(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.any(X509v3CertificateBuilderHolder.class), Mockito.any(X500Principal.class))).thenThrow(
                com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException.class);

        final X509Certificate certificate = certificateGenerator.generateCertificate(certificateInfo, keyIdentifier, keyPair.getPublic(), extensions);

        doAssertionsForGenerateCertificate(certificate);
    }

    /**
     * Method to test generation of {@link X509Certificate} for CA.
     *
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     * @throws com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException
     * @throws CertificateSignatureException
     */
    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificateCertificateSignatureException() throws CertificateSignatureException, com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {
        prepareCAData();

        Mockito.when(certGenInfoParser.getSubjectDNFromCertGenerationInfo(certificateInfo)).thenReturn(subjectDN);
        Mockito.when(certGenInfoParser.getIssuerDNFromCertGenerationInfo(certificateInfo)).thenReturn(issuerDN);
        Mockito.when(serialNumberGenerator.generateSerialNumber()).thenReturn(serialNumber);

        Mockito.when(dateUtil.getCurrentDate()).thenReturn(notBefore);
        Mockito.when(dateUtil.addDurationToDate(dateUtil.getCurrentDate(), certificateInfo.getValidity())).thenReturn(notAfter);

        Mockito.when(keyAccessProviderService.signCertificate(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.any(X509v3CertificateBuilderHolder.class), Mockito.any(X500Principal.class))).thenThrow(
                com.ericsson.oss.itpf.security.kaps.certificate.exception.CertificateSignatureException.class);

        final X509Certificate certificate = certificateGenerator.generateCertificate(certificateInfo, keyIdentifier, keyPair.getPublic(), extensions);

        doAssertionsForGenerateCertificate(certificate);
    }

    @Test(expected = CertificateServiceException.class)
    public void testGenerateCertificateCertificateServiceException() throws CertificateSignatureException, com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {
        prepareCAData();

        Mockito.when(certGenInfoParser.getSubjectDNFromCertGenerationInfo(certificateInfo)).thenReturn(subjectDN);
        Mockito.when(certGenInfoParser.getIssuerDNFromCertGenerationInfo(certificateInfo)).thenReturn(issuerDN);
        Mockito.when(serialNumberGenerator.generateSerialNumber()).thenReturn(serialNumber);

        Mockito.when(dateUtil.getCurrentDate()).thenReturn(notBefore);
        Mockito.when(dateUtil.addDurationToDate(dateUtil.getCurrentDate(), certificateInfo.getValidity())).thenReturn(notAfter);

        Mockito.when(keyAccessProviderService.signCertificate(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.any(X509v3CertificateBuilderHolder.class), Mockito.any(X500Principal.class))).thenThrow(
                com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException.class);

        final X509Certificate certificate = certificateGenerator.generateCertificate(certificateInfo, keyIdentifier, keyPair.getPublic(), extensions);

        doAssertionsForGenerateCertificate(certificate);
    }

    @Test(expected = UnsupportedCertificateVersionException.class)
    public void testGenerateCertificateUnsupportedCertificateVersionException() throws CertificateSignatureException, com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {
        prepareCAData();

        Mockito.when(certGenInfoParser.getSubjectDNFromCertGenerationInfo(certificateInfo)).thenReturn(subjectDN);
        Mockito.when(certGenInfoParser.getIssuerDNFromCertGenerationInfo(certificateInfo)).thenReturn(issuerDN);
        Mockito.when(serialNumberGenerator.generateSerialNumber()).thenReturn(serialNumber);

        Mockito.when(dateUtil.getCurrentDate()).thenReturn(notBefore);
        Mockito.when(dateUtil.addDurationToDate(dateUtil.getCurrentDate(), certificateInfo.getValidity())).thenReturn(notAfter);
        certificateInfo.setVersion(null);

        Mockito.when(keyAccessProviderService.signCertificate(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.any(X509v3CertificateBuilderHolder.class), Mockito.any(X500Principal.class))).thenReturn(x509Certificate);

        final X509Certificate certificate = certificateGenerator.generateCertificate(certificateInfo, keyIdentifier, keyPair.getPublic(), extensions);

        doAssertionsForGenerateCertificate(certificate);
    }

    private void prepareCAData() {
        serialNumber = "0";
        issuerDN = "CN = MyRoot";
        subjectDN = "CN=MyRoot";
        publicKey = x509Certificate.getPublicKey();
        signatureAlgorithm = "MD5withRSA";
        setCertificateGenerationInfoData();
    }

    private void prepareEntityData() {
        serialNumber = "0";
        issuerDN = "CN = MyRoot";
        subjectDN = "CN=MyRoot";
        publicKey = x509Certificate.getPublicKey();
        signatureAlgorithm = "MD5withRSA";
        setCertificateGenerationInfoData();
    }

    private void setCertificateGenerationInfoData() {
        certificateInfo = new CertificateGenerationInfo();
        certificateInfo.setSignatureAlgorithm(prepareSignatureAlgorithm());
        certificateInfo.setIssuerSignatureAlgorithm(prepareSignatureAlgorithm());
        certificateInfo.setVersion(CertificateVersion.V3);
        certificateInfo.setIssuerUniqueIdentifier(true);
        certificateInfo.setSubjectUniqueIdentifier(true);
        certificateInfo.setValidity(duration);
        certificateInfo.setIssuerCA(certificateAuthority);

        certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName("ROOT_CA");
        certificateAuthority.setRootCA(true);
        Certificate activeCertificate = new Certificate();
        activeCertificate.setX509Certificate(x509Certificate);
        activeCertificate.setStatus(CertificateStatus.ACTIVE);
        certificateAuthority.setActiveCertificate(activeCertificate);
        final Map<SubjectFieldType, String> issuerSubjectDN = new HashMap<SubjectFieldType, String>();
        issuerSubjectDN.put(SubjectFieldType.COMMON_NAME, "RootCA");
        issuerSubjectDN.put(SubjectFieldType.COUNTRY_NAME, "US");
        issuerSubjectDN.put(SubjectFieldType.ORGANIZATION, "TCS");
        issuerSubjectDN.put(SubjectFieldType.ORGANIZATION_UNIT, "Security");
        certificateInfo.setIssuerCA(certificateAuthority);
        certificateInfo.setCAEntityInfo(certificateAuthority);

    }

    private void doAssertionsForGenerateCertificate(final X509Certificate certificate) {
        assertNotNull(certificate);
        assertNotNull(certificate.getNotBefore());
        assertNotNull(certificate.getNotAfter());
        assertEquals(serialNumber, certificate.getSerialNumber() + "");
        assertEquals(addDurationToDate(certificate.getNotBefore(), duration), certificate.getNotAfter());
        assertNotNull(certificate.getPublicKey());
        assertEquals(signatureAlgorithm, certificate.getSigAlgName());
        assertEquals(subjectDN, certificate.getSubjectDN().toString());
    }
}
