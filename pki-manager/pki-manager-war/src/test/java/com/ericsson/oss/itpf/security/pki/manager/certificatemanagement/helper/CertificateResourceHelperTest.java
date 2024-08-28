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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SubjectSetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.dto.DownloadDTO;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util.CertificateUtil;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.rest.common.KeyStoreHelper;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.CommonUtil;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Resources.class)
@PowerMockIgnore({"java.net.ssl", "javax.security.auth.x500.X500Principal"})
public class CertificateResourceHelperTest {

    @InjectMocks
    CertificateResourceHelper certificateResourceHelper;

    @Spy
    Logger logger = LoggerFactory.getLogger(CertificateResourceHelper.class);

    @Mock
    CertificateUtil certificateUtil;

    @Mock
    Resource resource;

    @Mock
    KeyStoreHelper keyStoreHelper;

    @Mock
    CommonUtil commonUtil;

    Certificate certificate;
    SetUPData setUPData;
    SubjectSetUPData subjectSetUpData;

    List<Certificate> certificates;

    private static final EntityType entityType = EntityType.CA_ENTITY;
    private static final String DIRECTORY_NAME_VALUE = "Directory1";

    @Before
    public void setUp() throws Exception {

        setUPData = new SetUPData();
        subjectSetUpData = new SubjectSetUPData();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        final SubjectAltName subjectAltName = new SubjectAltName();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        certificates = new ArrayList<Certificate>();
        certificates.add(certificate);

        subjectAltNameField.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        subjectAltNameField.setValue(getSubjectAltNameString(DIRECTORY_NAME_VALUE));
        subjectAltNameFields.add(subjectAltNameField);

        certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        final X509Certificate x509Certificate = setUPData.getX509Certificate("certificates/ENMRootCA.crt");
        certificate.setX509Certificate(x509Certificate);
        final Subject subject = subjectSetUpData.getSubject("MyRoot");
        certificateAuthority.setName("MyRoot");
        certificateAuthority.setSubject(subject);
        certificate.setId(1);
        certificate.setSubject(subject);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        certificate.setIssuer(certificateAuthority);
        certificate.setSubjectAltName(subjectAltName);

    }

    @Test
    public void testGetCertificateBasicDetailsList() throws Exception {

        Mockito.when(certificateUtil.getEntityType(certificate.getX509Certificate().getBasicConstraints())).thenReturn(entityType);
        certificateResourceHelper.getCertificateBasicDetailsList(certificate);

    }

    @Test
    public void testGetIgnoredProperties() throws Exception {

        final String properties = "id";
        certificateResourceHelper.getIgnoredProperties(properties);

    }

    private AbstractSubjectAltNameFieldValue getSubjectAltNameString(final String value) {
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(value);

        return subjectAltNameString;
    }

    @Test
    public void testGetLatestCertificatesForSummary() throws Exception {

        certificateResourceHelper.getLatestCertificatesForSummary(certificates);

    }

    @Test
    public void testCreateKeyStoreForCertificates() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final DownloadDTO downloadDTO = setUPData.getDownloadDTO();
        final List<Certificate> certList = getCertificatesForDownload();

        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo();
        PowerMockito.when(keyStoreHelper.createKeyStoreInfo(Mockito.anyString(), Mockito.any(KeyStoreType.class), Mockito.anyString(), Mockito.anyString())).thenReturn(keyStoreInfo);

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(keyStoreHelper.createKeyStore(Mockito.any(KeyStoreInfo.class), Mockito.anyListOf(Certificate.class))).thenReturn("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        final File[] files = certificateResourceHelper.createKeyStoreForCertificates(downloadDTO, certList);
        assertNotNull(files);
        assertEquals("ARJ_Root-35c35df3596fc0e6-1450954693459.jks", files[0].getName());

    }

    @Test
    public void testCreateKeyStoreForCertificates_Subject_Null() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final DownloadDTO downloadDTO = setUPData.getDownloadDTO();
        final List<Certificate> certList = getCertificatesForDownload();
        certList.get(0).setSubject(null);

        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo();
        PowerMockito.when(keyStoreHelper.createKeyStoreInfo(Mockito.anyString(), Mockito.any(KeyStoreType.class), Mockito.anyString(), Mockito.anyString())).thenReturn(keyStoreInfo);

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(keyStoreHelper.createKeyStore(Mockito.any(KeyStoreInfo.class), Mockito.anyListOf(Certificate.class))).thenReturn(
                "certificates/certificate-35c35df3596fc0e6-1450954693459.jks");

        final File[] files = certificateResourceHelper.createKeyStoreForCertificates(downloadDTO, certList);
        assertNotNull(files);
        assertEquals("certificate-35c35df3596fc0e6-1450954693459.jks", files[0].getName());

    }

    @Test
    public void testCreateKeyStoreForCertificates_Subject_Empty() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final DownloadDTO downloadDTO = setUPData.getDownloadDTO();
        final List<Certificate> certList = getCertificatesForDownload();
        certList.get(0).setSubject(subjectSetUpData.getSubject());

        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo();
        PowerMockito.when(keyStoreHelper.createKeyStoreInfo(Mockito.anyString(), Mockito.any(KeyStoreType.class), Mockito.anyString(), Mockito.anyString())).thenReturn(keyStoreInfo);

        PowerMockito.mockStatic(Resources.class);
        Mockito.when(keyStoreHelper.createKeyStore(Mockito.any(KeyStoreInfo.class), Mockito.anyListOf(Certificate.class))).thenReturn("certificates/certificate-35c35df3596fc0e6-1450954693459.jks");
        final File[] files = certificateResourceHelper.createKeyStoreForCertificates(downloadDTO, certList);
        assertNotNull(files);
        assertEquals("certificate-35c35df3596fc0e6-1450954693459.jks", files[0].getName());

    }

    @Test
    public void testCreateKeyStoreForCertificates_Subject_CN_Empty() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final DownloadDTO downloadDTO = setUPData.getDownloadDTO();
        final List<Certificate> certList = getCertificatesForDownload();
        certList.get(0).setSubject(subjectSetUpData.getSubject("Tcs", "Ericsson"));

        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo();
        PowerMockito.when(keyStoreHelper.createKeyStoreInfo(Mockito.anyString(), Mockito.any(KeyStoreType.class), Mockito.anyString(), Mockito.anyString())).thenReturn(keyStoreInfo);

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(keyStoreHelper.createKeyStore(Mockito.any(KeyStoreInfo.class), Mockito.anyListOf(Certificate.class))).thenReturn(
                "certificates/certificate-35c35df3596fc0e6-1450954693459.jks");

        final File[] files = certificateResourceHelper.createKeyStoreForCertificates(downloadDTO, certList);
        assertNotNull(files);
        assertEquals("certificate-35c35df3596fc0e6-1450954693459.jks", files[0].getName());

    }

    @Test
    public void testCreateKeyStoreForCertificates_Subject_Contains_CN() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final DownloadDTO downloadDTO = setUPData.getDownloadDTO();
        final List<Certificate> certList = getCertificatesForDownload();
        certList.get(0).setSubject(subjectSetUpData.getSubject("ARJ_Root", "Tcs", "Ericsson"));

        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo();
        PowerMockito.when(keyStoreHelper.createKeyStoreInfo(Mockito.anyString(), Mockito.any(KeyStoreType.class), Mockito.anyString(), Mockito.anyString())).thenReturn(keyStoreInfo);

        PowerMockito.mockStatic(Resources.class);
        Mockito.when(keyStoreHelper.createKeyStore(Mockito.any(KeyStoreInfo.class), Mockito.anyListOf(Certificate.class))).thenReturn("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        final File[] files = certificateResourceHelper.createKeyStoreForCertificates(downloadDTO, certList);
        assertNotNull(files);
        assertEquals("ARJ_Root-35c35df3596fc0e6-1450954693459.jks", files[0].getName());

    }

    @Test
    public void testGetCertificateResponse() throws Exception {

        boolean[] keyUsages = new boolean[2];
        keyUsages[1] = true;
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        final KeyUsageType keyUsageType = KeyUsageType.CRL_SIGN;
        keyUsageTypes.add(keyUsageType);

        final List<String> extendedKeyUsages = certificate.getX509Certificate().getExtendedKeyUsage();
        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        extendedKeyUsage.setCritical(false);
        final List<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.ANY_EXTENDED_KEY_USAGE);
        keyPurposeIds.add(KeyPurposeId.ID_KP_CODE_SIGNING);
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIds);

        final X509Certificate x509Certificate = certificate.getX509Certificate();

        PowerMockito.mockStatic(RSAKey.class);

        Mockito.when(certificateUtil.getEntityType(certificate.getX509Certificate().getBasicConstraints())).thenReturn(entityType);
        Mockito.when(certificateUtil.getKeyUsage(keyUsages)).thenReturn(keyUsageTypes);
        Mockito.when(commonUtil.getExtendedKeyUsage(extendedKeyUsages)).thenReturn(keyPurposeIds);
        Mockito.when(commonUtil.getCRLDistributionPoint(x509Certificate)).thenReturn(extendedKeyUsages);

        certificateResourceHelper.getCertificateResponse(certificate);
    }

    private List<Certificate> getCertificatesForDownload() throws IOException, CertificateException {
        final List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(setUPData.createSubCACertificate("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer"));
        return certificates;
    }

}
