package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
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
import java.security.Security;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.Duration;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExtCAMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class CertificateModelMapperTest {

    @InjectMocks
    CertificateModelMapper certificateModelMapper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CAEntityMapper caEntityMapper;

    @Mock
    Subject subject;

    @Mock
    CertificateAuthority issuer;

    @Mock
    Duration validity;

    @Mock
    Algorithm algorithm;

    @Mock
    CertificateAuthority cAEntityInfo;

    @Mock
    EntityInfo entityInfo;

    @Mock
    PKCS10CertificationRequestHolder PKCS10CertificationRequestHolder;

    @Mock
    PKCS10CertificationRequest PKCS10CertificationRequest;

    @Mock
    CRMFRequestHolder CRMFRequestHolder;

    @Mock
    CertificateRequestMessage CRMFRequest;

    @Mock
    Logger logger;

    @Mock
    ExtCAMapper extCAMapper;

    private static SetUPData setUPData = new SetUPData();;
    Certificate expectedCertificate;
    CertificateData certificateData;
    CAEntityData issuerCA = new CAEntityData();

    @Before
    public void setUp() throws CertificateEncodingException, CertificateException, IOException {

        String filePath = "certificates/ENMRootCA.crt";
        certificateData = setUPData.createCertificateData(filePath, "3454634");

        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        certificateAuthorityData.setSubjectDN("CN=ENMSubCA");
        issuerCA.setCertificateAuthorityData(certificateAuthorityData);
        issuerCA.setExternalCA(false);
        certificateData.setIssuerCA(issuerCA);
        certificateData.setIssuerCertificate(certificateData);

        expectedCertificate = new Certificate();
        expectedCertificate.setId(certificateData.getId());
        expectedCertificate.setSerialNumber(certificateData.getSerialNumber());

        expectedCertificate.setNotBefore(certificateData.getNotBefore());
        expectedCertificate.setNotAfter(certificateData.getNotAfter());
        expectedCertificate.setStatus(CertificateStatus.getStatus(certificateData.getStatus()));
        expectedCertificate.setIssuedTime(certificateData.getIssuedTime());
        expectedCertificate.setSubjectAltName(JsonUtil.getObjectFromJson(SubjectAltName.class, certificateData.getSubjectAltName()));
        expectedCertificate.setIssuerCertificate(mapToIssuerCertificate(certificateData.getIssuerCertificate()));
        final X509CertificateHolder certificateHolder = new X509CertificateHolder(certificateData.getCertificate());
        final X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(Constants.PROVIDER_NAME).getCertificate(certificateHolder);
        expectedCertificate.setX509Certificate(x509Certificate);
    }

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @Test
    public void testFromObjectModel() throws Exception {

        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");
        certificate.setSubject(subject);
        certificate.setIssuer(issuer);
        CAEntityData caEntityData = new CAEntityData();
        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.getCertificateDatas();
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificate.getIssuer().getName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        final CertificateData certificateData = certificateModelMapper.fromObjectModel(certificate);

    }

    @Test
    public void testCertificateDataToCertificateObjectModel() throws Exception {

        Mockito.when(caEntityMapper.toAPIFromModel(certificateData.getIssuerCA())).thenReturn(new CAEntity());

        assertEquals(expectedCertificate, certificateModelMapper.toCertificate(certificateData));

    }

    @Test
     public void testtoCertificateForTDPSInfo() throws Exception {

        Mockito.when(caEntityMapper.toAPIFromModelForCAName(certificateData.getIssuerCA())).thenReturn(new CAEntity());
        certificateModelMapper.toCertificateForTDPSInfo(certificateData);

        issuerCA.setExternalCA(true);
        certificateData.setSubjectDN("CN=ENMSubCA");
        Mockito.when(extCAMapper.toAPIFromModel(certificateData.getIssuerCA())).thenReturn(new ExtCA());
        certificateModelMapper.toCertificateForTDPSInfo(certificateData);

    }


    @Test
    public void testToCertificateGenerationInfoData() {
        CertificateGenerationInfo certificateGenerationInfo = new CertificateGenerationInfo();
        certificateGenerationInfo.setId(1);
        certificateGenerationInfo.setValidity(validity);
        certificateGenerationInfo.setSkewCertificateTime(validity);
        certificateGenerationInfo.setKeyGenerationAlgorithm(algorithm);
        certificateGenerationInfo.setSignatureAlgorithm(algorithm);
        certificateGenerationInfo.setIssuerSignatureAlgorithm(algorithm);
        certificateGenerationInfo.setCAEntityInfo(cAEntityInfo);
        certificateGenerationInfo.setEntityInfo(entityInfo);
        certificateModelMapper.toCertificateGenerationInfoData(certificateGenerationInfo);
    }

    @Test
    public void testCertificateDatasToCertificateObjectModels() throws CertificateException, IOException {

        final List<Certificate> expectedCertificateList = new ArrayList<>();
        expectedCertificateList.add(expectedCertificate);
        final List<CertificateData> certificateDatas = new ArrayList<>();
        certificateDatas.add(certificateData);

        Mockito.when(caEntityMapper.toAPIFromModel(certificateData.getIssuerCA())).thenReturn(new CAEntity());

        assertEquals(expectedCertificateList, certificateModelMapper.toObjectModel(certificateDatas));
    }

    @Test
    public void testToPKCS10CertificateRequestData() throws IOException {

        final CertificateRequestData expectedCertificateRequestData = new CertificateRequestData();

        final byte[] certificateRequest = new byte[1];
        CertificateRequest certReq = new CertificateRequest();

        certReq.setCertificateRequestHolder(PKCS10CertificationRequestHolder);

        expectedCertificateRequestData.setCsr(certificateRequest);
        expectedCertificateRequestData.setStatus(CertificateRequestStatus.ISSUED.getId());

        Mockito.when(PKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(PKCS10CertificationRequest);
        Mockito.when(PKCS10CertificationRequest.getEncoded()).thenReturn(certificateRequest);

        assertEquals(expectedCertificateRequestData, certificateModelMapper.toCertificateRequestData(certReq));
    }

    @Test
    public void testToCrmfCertificateRequestData() throws IOException {

        final byte[] certificateRequest = new byte[1];
        final CertificateRequest certReq = new CertificateRequest();

        certReq.setCertificateRequestHolder(CRMFRequestHolder);

        Mockito.when(CRMFRequestHolder.getCertificateRequest()).thenReturn(CRMFRequest);
        Mockito.when(CRMFRequest.getEncoded()).thenReturn(certificateRequest);

        final CertificateRequestData expectedCertificateRequestData = new CertificateRequestData();
        expectedCertificateRequestData.setCsr(certificateRequest);
        expectedCertificateRequestData.setStatus(CertificateRequestStatus.ISSUED.getId());

        assertEquals(expectedCertificateRequestData, certificateModelMapper.toCertificateRequestData(certReq));
    }

    private Certificate mapToIssuerCertificate(final CertificateData certificateData) {

        final Certificate certificate = new Certificate();
        certificate.setId(certificateData.getId());
        certificate.setSerialNumber(certificateData.getSerialNumber());

        certificate.setNotBefore(certificateData.getNotBefore());
        certificate.setNotAfter(certificateData.getNotAfter());
        certificate.setStatus(CertificateStatus.getStatus(certificateData.getStatus()));
        certificate.setIssuedTime(certificateData.getIssuedTime());
        if (certificateData.getSubjectDN() != null) {
            certificate.setSubject(new Subject().fromASN1String(certificateData.getSubjectDN()));
        }
        certificate.setSubjectAltName(JsonUtil.getObjectFromJson(SubjectAltName.class, certificateData.getSubjectAltName()));
        return certificate;
    }
}
