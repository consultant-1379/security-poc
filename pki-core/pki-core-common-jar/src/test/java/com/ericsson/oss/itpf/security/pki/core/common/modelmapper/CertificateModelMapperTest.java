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
package com.ericsson.oss.itpf.security.pki.core.common.modelmapper;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.xml.datatype.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.common.utils.CertificateGenerationInfoParser;
import com.ericsson.oss.itpf.security.pki.core.common.utils.DateUtil;

@RunWith(MockitoJUnitRunner.class)
public class CertificateModelMapperTest {

    @InjectMocks
    CertificateModelMapper certificateModelMapper;

    @Mock
    DateUtil dateUtil;

    @Mock
    CertificateGenerationInfoParser certificateGenerationInfoParser;

    @Mock
    Logger logger;

    @Mock
    CertificatePersistenceHelper persistenceHelper;

    private CertificateGenerationInfo certGenerationInfo;
    private byte[] certificationRequest = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    private CertificateAuthorityData certificateAuthorityData;
    private EntityInfoData entityData;

    @Before
    public void setUp() {
        certGenerationInfo = new CertificateGenerationInfo();
        certificateAuthorityData = new CertificateAuthorityData();
        entityData = new EntityInfoData();
    }

    @Test
    public void testMapToCertificateGenerationInfoData_CAEntityInfo_ROOT() throws DatatypeConfigurationException {
        testMapToCertificateGenerationInfoData_Setup_CAEntityInfo_ROOT();
        CertificateGenerationInfoData certificateGenerationInfoData = certificateModelMapper.mapToCertificateGenerationInfoData(certGenerationInfo, certificationRequest, certificateAuthorityData,
                entityData);
        Assert.assertEquals(certGenerationInfo.getId(), certificateGenerationInfoData.getId());
    }

    @Test
    public void testMapToCertificateGenerationInfoData_CAEntityInfo() throws DatatypeConfigurationException {
        testMapToCertificateGenerationInfoData_Setup_CAEntityInfo();
        CertificateGenerationInfoData certificateGenerationInfoData = certificateModelMapper.mapToCertificateGenerationInfoData(certGenerationInfo, certificationRequest, certificateAuthorityData,
                entityData);
        Assert.assertEquals(certGenerationInfo.getId(), certificateGenerationInfoData.getId());
    }

    @Test
    public void testMapToCertificateGenerationInfoData() throws DatatypeConfigurationException {
        testMapToCertificateGenerationInfoData_Setup();
        CertificateGenerationInfoData certificateGenerationInfoData = certificateModelMapper.mapToCertificateGenerationInfoData(certGenerationInfo, certificationRequest, certificateAuthorityData,
                entityData);
        Assert.assertEquals(certGenerationInfo.getId(), certificateGenerationInfoData.getId());
    }

    @Test
    public void testMapToCertificate_SubjectAltName() throws CertificateException, IOException {
        CertificateData certificateData = getCertificateData();
        certificateData.setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":true,\"subjectAltNameFields\":[{\"type\":\"IP_ADDRESS\",\"value\":null}]}");
        com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate certifiacteReturn = certificateModelMapper.mapToCertificate(certificateData);
        Assert.assertEquals(certifiacteReturn.getId(), certificateData.getId());
        Assert.assertEquals(certifiacteReturn.getSerialNumber(), certificateData.getSerialNumber());
    }

    @Test
    public void testMapToCertificate_IssuerCA() throws CertificateException, IOException {
        CertificateData certificateData = getCertificateData();
        CertificateAuthorityData certificateAuthorityData = getIssuerCA();
        certificateData.setIssuerCA(certificateAuthorityData);
        com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate certifiacteReturn = certificateModelMapper.mapToCertificate(certificateData);
        Assert.assertEquals(certifiacteReturn.getId(), certificateData.getId());
        Assert.assertEquals(certifiacteReturn.getSerialNumber(), certificateData.getSerialNumber());
    }

    @Test
    public void testMapToCertificate() throws CertificateException, IOException {
        CertificateData certificateData = getCertificateData();
        com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate certifiacteReturn = certificateModelMapper.mapToCertificate(certificateData);
        Assert.assertEquals(certifiacteReturn.getId(), certificateData.getId());
        Assert.assertEquals(certifiacteReturn.getSerialNumber(), certificateData.getSerialNumber());
    }

    private CertificateAuthorityData getIssuerCA() {
        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setId(123);
        certificateAuthorityData.setName("RootCA");
        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setStatus(CAStatus.ACTIVE);
        return certificateAuthorityData;
    }

    private CertificateData getCertificateData() throws CertificateEncodingException, CertificateException, IOException {
        CertificateData certificateData = new CertificateData();
        certificateData.setId(123);

        certificateData.setCertificate(getX509Certificate("MyRoot.crt").getEncoded());
        return certificateData;
    }

    private X509Certificate getX509Certificate(final String filename) throws IOException, CertificateException {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(filename);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }

    private void testMapToCertificateGenerationInfoData_Setup() throws DatatypeConfigurationException {

        testMapToCertificateGenerationInfoData_Setup(null, true);

    }

    private void testMapToCertificateGenerationInfoData_Setup_CAEntityInfo() throws DatatypeConfigurationException {
        CertificateAuthority caEntityInfo = new CertificateAuthority();
        caEntityInfo.setId(1234);
        caEntityInfo.setRootCA(false);
        testMapToCertificateGenerationInfoData_Setup(caEntityInfo, true);

    }

    private void testMapToCertificateGenerationInfoData_Setup_CAEntityInfo_ROOT() throws DatatypeConfigurationException {
        CertificateAuthority caEntityInfo = new CertificateAuthority();
        caEntityInfo.setId(1234);
        caEntityInfo.setRootCA(true);
        testMapToCertificateGenerationInfoData_Setup(caEntityInfo, false);

    }

    private void testMapToCertificateGenerationInfoData_Setup(CertificateAuthority caEntityInfo, boolean skewCertificateTime) throws DatatypeConfigurationException {
        certGenerationInfo.setId(1234);
        certGenerationInfo.setRequestType(RequestType.MODIFY);
        certificateAuthorityData.setId(234);
        certificateAuthorityData.setName("ABC");
        certificateAuthorityData.setStatus(CAStatus.ACTIVE);
        entityData.setId(456);
        entityData.setStatus(EntityStatus.ACTIVE);
        DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        formatter.setLenient(false);
        Date d = null;
        try {
            d = formatter.parse("2019-07-11 10:55:21");
        } catch (ParseException e) {

            e.printStackTrace();
        }
        Duration validity = datatypeFactory.newDuration(d.getTime());
        certGenerationInfo.setValidity(validity);
        CertificateAuthority issuerCA = new CertificateAuthority();
        issuerCA.setId(456);
        issuerCA.setName("qwer");
        issuerCA.setStatus(CAStatus.ACTIVE);
        certGenerationInfo.setIssuerCA(issuerCA);
        if (skewCertificateTime)
            certGenerationInfo.setSkewCertificateTime(validity);
        certGenerationInfo.setCAEntityInfo(caEntityInfo);
        entityData.setName("Entity");

    }

    @Test
    public void testMapToKeyData() {
        KeyIdentifier keyIdentifier = new KeyIdentifier();
        keyIdentifier.setId("654");
        KeyIdentifierData identifierData = certificateModelMapper.mapToKeyData(keyIdentifier, KeyPairStatus.ACTIVE);
        Assert.assertEquals(identifierData.getKeyIdentifier(), keyIdentifier.getId());
        Assert.assertEquals(identifierData.getStatus(), KeyPairStatus.ACTIVE);
    }

}
