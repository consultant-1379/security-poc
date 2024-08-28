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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.mapper;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;

import javax.xml.datatype.*;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;

@RunWith(MockitoJUnitRunner.class)
public class CertificateModelMapperTest extends BaseTest {

    @InjectMocks
    private CertificateModelMapper modelMapper;

    @Mock
    private PKCS10CertificationRequest certificationRequest;

    private CertificateGenerationInfo certificateGenerationInfo;
    private AlgorithmData algorithmData;
    private CertificateAuthority certificateAuthority;
    private CertificateAuthorityData certificateAuthorityData;
    private CertificateData certificateData;
    private X509Certificate x509Certificate;
    private Duration duration;
    private EntityInfoData entityData;

    private KeyPair keyPair;

    private static final String DURATION = "P2Y";

    /**
     * Prepares initial data.
     * 
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws CertificateException
     */
    @Before
    public void setUp() throws NoSuchAlgorithmException, CertificateException, IOException {
        certificateGenerationInfo = new CertificateGenerationInfo();
        certificateAuthority = new CertificateAuthority();
        certificateAuthorityData = new CertificateAuthorityData();
        algorithmData = new AlgorithmData();
        entityData = new EntityInfoData();

        new KeyIdentifierData();

        x509Certificate = getCertificate("src/test/resources/MyRoot.crt");

        final Algorithm keyGenerationAlgorithm = prepareKeyGenerationAlgorithm();

        certificateGenerationInfo.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
    }

    /**
     * Method to test mapping to {@link Certificate} model.
     * 
     * @throws IOException
     * @throws CertificateException
     * @throws CertificateEncodingException
     * @throws CertificateException
     * @throws DatatypeConfigurationException
     * 
     */
    @Test
    public void testToCertificate() throws CertificateEncodingException, DatatypeConfigurationException, CertificateException {

        setCertificateData();

        final Certificate certificate = modelMapper.mapToCertificate(certificateData);

        assertNotNull(certificate);
        assertEquals(certificateData.getId(), certificate.getId());
        assertEquals(certificateData.getSerialNumber(), certificate.getSerialNumber());
        assertEquals(certificateData.getStatus(), certificate.getStatus());
        assertEquals(certificateData.getNotAfter(), addDurationToDate(certificate.getNotBefore(), duration));
        assertEquals(certificateData.getIssuerCA().getName(), certificate.getIssuer().getName());
    }

    /**
     * Method to test mapping to {@link CertificateAuthority} model.
     */
    @Test
    public void testMapToKeyData() {
        final KeyIdentifier keyIdentifier = new KeyIdentifier();
        keyIdentifier.setId("K0000001");
        final KeyIdentifierData keyData = modelMapper.mapToKeyData(keyIdentifier, KeyPairStatus.ACTIVE);

        assertNotNull(keyData);
        assertEquals(keyData.getStatus(), KeyPairStatus.ACTIVE);
    }

    /**
     * Method to test mapping to {@link CertificateGenerationInfo} model.
     * 
     * @throws DatatypeConfigurationException
     * @throws IOException
     * 
     */
    @Test
    public void testMapToCertificateGenerationInfoDataForRootCA() throws DatatypeConfigurationException, IOException {
        prepareCertificateGenerationInfoDataForRootCA();

        Mockito.when(persistenceHelper.getAlgorithmData(certificateGenerationInfo.getKeyGenerationAlgorithm())).thenReturn(algorithmData);

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        final CertificateGenerationInfoData certificateGenerationInfoData = modelMapper.mapToCertificateGenerationInfoData(certificateGenerationInfo, certificationRequest.getEncoded(),
                certificateAuthorityData, null);

        assertNotNull(certificateGenerationInfoData);
        assertEquals(certificateGenerationInfoData.getCertificateVersion(), certificateGenerationInfo.getVersion());
        assertEquals(certificateGenerationInfoData.isSubjectUniqueIdentifier(), certificateGenerationInfo.isSubjectUniqueIdentifier());
        assertEquals(certificateGenerationInfoData.isIssuerUniqueIdentifier(), certificateGenerationInfo.isIssuerUniqueIdentifier());
        assertEquals(certificateGenerationInfoData.getCertificateExtensionsJSONData(), JsonUtil.getJsonFromObject(certificateGenerationInfo.getCertificateExtensions()));
        assertEquals(certificateGenerationInfoData.getRequestType(), certificateGenerationInfo.getRequestType());
    }

    /**
     * Method to test mapping to {@link CertificateGenerationInfo} model.
     * 
     * @throws DatatypeConfigurationException
     * @throws IOException
     * 
     */
    @Test
    public void testMapToCertificateGenerationInfoDataForSubCA() throws DatatypeConfigurationException, IOException {
        prepareCertificateGenerationInfoDataForSubCA();

        Mockito.when(persistenceHelper.getAlgorithmData(certificateGenerationInfo.getKeyGenerationAlgorithm())).thenReturn(algorithmData);

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        final CertificateGenerationInfoData certificateGenerationInfoData = modelMapper.mapToCertificateGenerationInfoData(certificateGenerationInfo, certificationRequest.getEncoded(),
                certificateAuthorityData, null);

        assertNotNull(certificateGenerationInfoData);
        assertEquals(certificateGenerationInfoData.getCertificateVersion(), certificateGenerationInfo.getVersion());
        assertEquals(certificateGenerationInfoData.isSubjectUniqueIdentifier(), certificateGenerationInfo.isSubjectUniqueIdentifier());
        assertEquals(certificateGenerationInfoData.isIssuerUniqueIdentifier(), certificateGenerationInfo.isIssuerUniqueIdentifier());
        assertEquals(certificateGenerationInfoData.getCertificateExtensionsJSONData(), JsonUtil.getJsonFromObject(certificateGenerationInfo.getCertificateExtensions()));
        assertEquals(certificateGenerationInfoData.getRequestType(), certificateGenerationInfo.getRequestType());
    }

    /**
     * Method to test mapping to {@link CertificateGenerationInfo} model.
     * 
     * @throws DatatypeConfigurationException
     * @throws IOException
     * 
     */
    @Test
    public void testMapToCertificateGenerationInfoDataForEntity() throws DatatypeConfigurationException, IOException {
        prepareCertificateGenerationInfoDataForEntity();

        Mockito.when(persistenceHelper.getAlgorithmData(certificateGenerationInfo.getKeyGenerationAlgorithm())).thenReturn(algorithmData);

        final CertificateGenerationInfoData certificateGenerationInfoData = modelMapper.mapToCertificateGenerationInfoData(certificateGenerationInfo, certificationRequest.getEncoded(), null,
                entityData);

        assertNotNull(certificateGenerationInfoData);
        assertEquals(certificateGenerationInfoData.getCertificateVersion(), certificateGenerationInfo.getVersion());
        assertEquals(certificateGenerationInfoData.isSubjectUniqueIdentifier(), certificateGenerationInfo.isSubjectUniqueIdentifier());
        assertEquals(certificateGenerationInfoData.isIssuerUniqueIdentifier(), certificateGenerationInfo.isIssuerUniqueIdentifier());
        assertEquals(certificateGenerationInfoData.getCertificateExtensionsJSONData(), JsonUtil.getJsonFromObject(certificateGenerationInfo.getCertificateExtensions()));
        assertEquals(certificateGenerationInfoData.getRequestType(), certificateGenerationInfo.getRequestType());
    }

    private void prepareRootCAData() {
        certificateAuthority = prepareCAData(true);
        certificateGenerationInfo.setCAEntityInfo(certificateAuthority);
    }

    private void prepareSubCAData() {
        certificateAuthority = prepareCAData(false);
        final CertificateAuthority issuerCA = new CertificateAuthority();
        issuerCA.setName(ROOT_CA);
        certificateGenerationInfo.setCAEntityInfo(certificateAuthority);
        certificateGenerationInfo.setIssuerCA(issuerCA);
    }

    private void setEntityData() {
        final EntityInfo entityInfo = prepareEntityInfo();
        prepareSubCAData();
        certificateGenerationInfo.setCAEntityInfo(null);
        certificateGenerationInfo.setEntityInfo(entityInfo);
    }

    private void prepareCertificateGenerationInfoDataForRootCA() throws DatatypeConfigurationException {
        prepareRootCAData();
        certificateGenerationInfo.setIssuerCA(certificateAuthority);
        setCommonDataForCertGenInfo();
    }

    private void setCertificateData() throws DatatypeConfigurationException, CertificateEncodingException {
        duration = DatatypeFactory.newInstance().newDuration(DURATION);
        final Date notBefore = new Date();
        final Date notAfter = addDurationToDate(notBefore, duration);
        final CertificateAuthorityData issuerCA = new CertificateAuthorityData();
        issuerCA.setName(ROOT_CA);

        certificateData = new CertificateData();
        certificateData.setId(1);
        certificateData.setNotBefore(notBefore);
        certificateData.setNotAfter(notAfter);
        certificateData.setSerialNumber("123456");
        certificateData.setStatus(CertificateStatus.ACTIVE);
        certificateData.setCertificate(x509Certificate.getEncoded());
        certificateData.setIssuerCA(issuerCA);
    }

    private void prepareCertificateGenerationInfoDataForSubCA() throws DatatypeConfigurationException {
        prepareSubCAData();
        setCommonDataForCertGenInfo();
    }

    private void prepareCertificateGenerationInfoDataForEntity() throws DatatypeConfigurationException {
        setEntityData();
        setCommonDataForCertGenInfo();
    }

    private void setCommonDataForCertGenInfo() throws DatatypeConfigurationException {
        final String SKEWDURATION = "PT9H0M30S";
        final Duration validity = DatatypeFactory.newInstance().newDuration(DURATION);
        final Duration skewDuration = DatatypeFactory.newInstance().newDuration(SKEWDURATION);

        certificateGenerationInfo.setValidity(validity);
        certificateGenerationInfo.setSkewCertificateTime(skewDuration);
        certificateGenerationInfo.setVersion(CertificateVersion.V3);
        certificateGenerationInfo.setRequestType(RequestType.NEW);
        certificateGenerationInfo.setIssuerUniqueIdentifier(false);
        certificateGenerationInfo.setSubjectUniqueIdentifier(false);
        certificateGenerationInfo.setSignatureAlgorithm(prepareSignatureAlgorithm());

        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        final List<CertificateExtension> certificateExtensionsList = new ArrayList<CertificateExtension>();

        final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
        final com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyIdentifier keyIdentifier = new com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyIdentifier();
        keyIdentifier.setAlgorithm(prepareKeyIdentifierAlgorithm(Constants.KEYIDENTIFIER_TYPE2));
        subjectKeyIdentifier.setCritical(true);
        subjectKeyIdentifier.setKeyIdentifier(keyIdentifier);
        certificateExtensionsList.add(subjectKeyIdentifier);
        certificateExtensions.setCertificateExtensions(certificateExtensionsList);
        certificateGenerationInfo.setCertificateExtensions(certificateExtensions);
    }
}
