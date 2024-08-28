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

import static org.mockito.Mockito.times;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;

@RunWith(MockitoJUnitRunner.class)
public class EntityModelMapperTest {

    @InjectMocks
    EntityModelMapper entityModelMapper;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificateAuthorityModelMapper caEntityMapper;

    private final static String NAME_PATH = "name";
    private EntityInfo entityInfo;
    private EntityInfoData entityInfoData;

    @Before
    public void setUp() {
        entityInfo = new EntityInfo();
        entityInfo.setId(123);
        entityInfo.setName("EntityInfo");
        entityInfo.setStatus(EntityStatus.ACTIVE);
        entityInfoData = new EntityInfoData();
    }

    @Test
    public void testFromAPIToModel_UPDATE() {
        Mockito.when(persistenceManager.findEntity(EntityInfoData.class, entityInfo.getId())).thenReturn(entityInfoData);
        EntityInfoData entiryInfoDataReturn = entityModelMapper.fromAPIToModel(entityInfo, OperationType.UPDATE);
        Mockito.verify(persistenceManager, times(1)).findEntity(EntityInfoData.class, entityInfo.getId());
    }

    @Test
    public void testFromAPIToModel_CREATE() {
        EntityInfoData entityInfoDataReturn = entityModelMapper.fromAPIToModel(entityInfo, OperationType.CREATE);
        Assert.assertEquals(entityInfo.getId(), entityInfoDataReturn.getId());
        Assert.assertEquals(entityInfo.getName(), entityInfoDataReturn.getName());
    }

    @Test
    public void testFromAPIToModel_SubjectAltName() {

        getSubjectAltNameField();
        EntityInfoData entityInfoDataReturn = entityModelMapper.fromAPIToModel(entityInfo, OperationType.CREATE);
        Assert.assertEquals(entityInfo.getId(), entityInfoDataReturn.getId());
        Assert.assertEquals(entityInfo.getName(), entityInfoDataReturn.getName());
    }

    @Test
    public void testFromAPIToModel_IssuerCA() {
        CertificateAuthorityData issuerData = new CertificateAuthorityData();
        getIssuerCA();
        Mockito.when(persistenceManager.findEntityByName(CertificateAuthorityData.class, entityInfo.getIssuer().getName(), NAME_PATH)).thenReturn(issuerData);
        EntityInfoData entityInfoDataReturn = entityModelMapper.fromAPIToModel(entityInfo, OperationType.CREATE);
        Assert.assertEquals(entityInfo.getId(), entityInfoDataReturn.getId());
        Assert.assertEquals(entityInfo.getName(), entityInfoDataReturn.getName());
    }

    @Test
    public void testFromAPIToModel_SubjectDN() {
        getSubjectDN();
        EntityInfoData entityInfoDataReturn = entityModelMapper.fromAPIToModel(entityInfo, OperationType.CREATE);
        Assert.assertEquals(entityInfo.getId(), entityInfoDataReturn.getId());
        Assert.assertEquals(entityInfo.getName(), entityInfoDataReturn.getName());
    }

    @Test
    public void testToAPIFromModel_SubjectAltName() throws CertificateException {
        testToAPIFromModel_SubjectAltName_Setup();
        EntityInfo entityInfoReturn = entityModelMapper.toAPIFromModel(entityInfoData);
        Assert.assertEquals(entityInfoData.getId(), entityInfoReturn.getId());
        Assert.assertEquals(entityInfoData.getName(), entityInfoReturn.getName());
    }

    @Test
    public void testToAPIFromModel_Issuer() throws CertificateException {
        setCertificateAuthorityData();
        EntityInfo entityInfoReturn = entityModelMapper.toAPIFromModel(entityInfoData);
        Assert.assertEquals(entityInfoData.getId(), entityInfoReturn.getId());
        Assert.assertEquals(entityInfoData.getName(), entityInfoReturn.getName());
    }

    private void testToAPIFromModel_SubjectAltName_Setup() {
        entityInfoData.setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":true,\"subjectAltNameFields\":[{\"type\":\"IP_ADDRESS\",\"value\":null}]}");
    }

    private void getSubjectDN() {
        Subject subject = new Subject();
        List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COUNTRY_NAME);
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        entityInfo.setSubject(subject);
    }

    private void getSubjectAltNameField() {
        SubjectAltName subjectAltName = new SubjectAltName();
        subjectAltName.setCritical(true);
        List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.IP_ADDRESS);
        subjectAltNameFields.add(subjectAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        entityInfo.setSubjectAltName(subjectAltName);
    }

    private void getIssuerCA() {
        CertificateAuthority issuer = new CertificateAuthority();
        issuer.setId(123);
        issuer.setName("Name");
        entityInfo.setIssuer(issuer);

    }

    private void setCertificateAuthorityData() {
        CertificateAuthorityData issuerCA = new CertificateAuthorityData();
        issuerCA.setId(123);
        issuerCA.setName("Name");
        issuerCA.setStatus(CAStatus.ACTIVE);
        entityInfoData.setIssuerCA(issuerCA);
    }

    private CertificateData getCertificateData() throws CertificateEncodingException, CertificateException, IOException {
        CertificateData certificateData = new CertificateData();
        certificateData.setId(123);

        certificateData.setCertificate(getX509Certificate("MyRoot.crt").getEncoded());
        return certificateData;
    }

    private X509Certificate getX509Certificate(final String filename) throws IOException, CertificateException {
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(filename);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(inputStream);
    }
}
