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

import java.security.cert.CertificateException;
import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;

@RunWith(MockitoJUnitRunner.class)
public class CertificateAuthorityModelMapperTest {

    @InjectMocks
    CertificateAuthorityModelMapper certificateAuthorityModelMapper;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CRLInfoMapper crlInfoMapper;

    @Mock
    CertificateModelMapper certificateModelMapper;

    private CertificateAuthority certificateAuthority;

    @Before
    public void setUp() {
        certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(1234L);
        certificateAuthority.setName("CertificateAuthority");
        certificateAuthority.setStatus(CAStatus.ACTIVE);
    }

    @Test
    public void testFromAPIModel_ACTIVE() {
        CertificateAuthorityData returnCertificateAuthorityData = certificateAuthorityModelMapper.fromAPIModel(certificateAuthority, OperationType.CREATE);
        Assert.assertEquals(certificateAuthority.getId(), returnCertificateAuthorityData.getId());
        Assert.assertEquals(certificateAuthority.getName(), returnCertificateAuthorityData.getName());
    }

    @Test
    public void testFromAPIModel() {
        certificateAuthority = testFormAPIModel_ACTIVE_Subject_Setup();
        CertificateAuthorityData certificateAuthorityData = testToAPIModel_Setup(CertificateStatus.ACTIVE);
        Mockito.when(persistenceManager.findEntity(CertificateAuthorityData.class, certificateAuthority.getId())).thenReturn(certificateAuthorityData);
        CertificateAuthorityData returnCertificateAuthorityData = certificateAuthorityModelMapper.fromAPIModel(certificateAuthority, OperationType.UPDATE);
        Assert.assertEquals(certificateAuthority.getId(), returnCertificateAuthorityData.getId());
        Assert.assertEquals(certificateAuthority.getName(), returnCertificateAuthorityData.getName());
    }

    @Test
    public void testFromAPIModel_ACTIVE_Subject() {
        certificateAuthority = testFormAPIModel_ACTIVE_Subject_Setup();
        CertificateAuthorityData returnCertificateAuthorityData = certificateAuthorityModelMapper.fromAPIModel(certificateAuthority, OperationType.CREATE);
        Assert.assertEquals(certificateAuthority.getId(), returnCertificateAuthorityData.getId());
        Assert.assertEquals(certificateAuthority.getName(), returnCertificateAuthorityData.getName());
    }

    private CertificateAuthority testFormAPIModel_ACTIVE_Subject_Setup() {
        Subject subject = new Subject();
        List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subject.setSubjectFields(subjectFields);
        certificateAuthority.setSubject(subject);
        return certificateAuthority;
    }

    @Test
    public void testFromAPIModel_ACTIVE_SubjectAltName() {
        certificateAuthority = testFromAPIModel_ACTIVE_SubjectAltName_Setup();
        CertificateAuthorityData returnCertificateAuthorityData = certificateAuthorityModelMapper.fromAPIModel(certificateAuthority, OperationType.CREATE);
        Assert.assertEquals(certificateAuthority.getId(), returnCertificateAuthorityData.getId());
        Assert.assertEquals(certificateAuthority.getName(), returnCertificateAuthorityData.getName());
    }

    private CertificateAuthority testFromAPIModel_ACTIVE_SubjectAltName_Setup() {
        SubjectAltName subjectAltName = new SubjectAltName();
        subjectAltName.setCritical(true);
        List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.IP_ADDRESS);
        subjectAltNameFields.add(subjectAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        certificateAuthority.setSubjectAltName(subjectAltName);
        return certificateAuthority;
    }

    @Test
    public void testFromAPIModel_ACTIVE_Issuer() {
        CertificateAuthority issuer = new CertificateAuthority();
        issuer.setId(123456);
        issuer.setName("Testing");
        issuer.setStatus(CAStatus.ACTIVE);
        certificateAuthority.setIssuer(issuer);
        CertificateAuthorityData returnCertificateAuthorityData = certificateAuthorityModelMapper.fromAPIModel(certificateAuthority, OperationType.CREATE);
        Assert.assertEquals(certificateAuthority.getId(), returnCertificateAuthorityData.getId());
        Assert.assertEquals(certificateAuthority.getName(), returnCertificateAuthorityData.getName());
    }

    @Test
    public void testToAPIModel_ACTIVE() throws CertificateException {
        CertificateAuthorityData certificateAuthorityData = testToAPIModel_Setup(CertificateStatus.ACTIVE);
        CertificateAuthority returnCertificateAuthority = certificateAuthorityModelMapper.toAPIModel(certificateAuthorityData);
        Assert.assertEquals(certificateAuthorityData.getId(), returnCertificateAuthority.getId());
        Assert.assertEquals(certificateAuthorityData.getName(), returnCertificateAuthority.getName());
    }

    @Test
    public void testToAPIModel_INACTIVE() throws CertificateException {
        CertificateAuthorityData certificateAuthorityData = testToAPIModel_Setup(CertificateStatus.INACTIVE);
        CertificateAuthority returnCertificateAuthority = certificateAuthorityModelMapper.toAPIModel(certificateAuthorityData);
        Assert.assertEquals(certificateAuthorityData.getId(), returnCertificateAuthority.getId());
        Assert.assertEquals(certificateAuthorityData.getName(), returnCertificateAuthority.getName());
    }

    private CertificateAuthorityData testToAPIModel_Setup(CertificateStatus certificateStatus) {
        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setId(123);
        certificateAuthorityData.setStatus(CAStatus.ACTIVE);
        Set<CRLInfoData> crlDatas = new HashSet<CRLInfoData>();
        CRLInfoData crlData = new CRLInfoData();
        crlData.setCrlNumber(12345);
        crlData.setId(12345);
        crlData.setStatus(CRLStatus.LATEST);
        certificateAuthorityData.setCrlDatas(crlDatas);
        crlDatas.add(crlData);
        certificateAuthorityData.setCrlDatas(crlDatas);
        Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        CertificateData certificateData = new CertificateData();
        certificateData.setId(123);
        certificateData.setSerialNumber("9874");
        certificateData.setStatus(certificateStatus);
        certificateDatas.add(certificateData);
        certificateAuthorityData.setCertificateDatas(certificateDatas);
        certificateAuthorityData.setSubjectDN("C=US, ST=Maryland, L=Pasadena, O=Brent Baccala, OU=FreeSoft,CN=www.freesoft.org/emailAddress=baccala@freesoft.org");
        certificateAuthorityData.setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":true,\"subjectAltNameFields\":[{\"type\":\"IP_ADDRESS\",\"value\":null}]}");
        certificateAuthorityData.setRootCA(false);
        CertificateAuthorityData issuerCA = new CertificateAuthorityData();
        issuerCA.setRootCA(true);
        issuerCA.setId(321);
        issuerCA.setName("CA");
        issuerCA.setStatus(CAStatus.ACTIVE);
        certificateAuthorityData.setIssuerCA(issuerCA);
        certificateAuthorityData.setId(12345);
        return certificateAuthorityData;
    }
}
