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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.*;
import java.util.HashSet;
import java.util.Set;

import javax.xml.datatype.DatatypeFactory;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.AlgorithmConfigurationModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.CertificateExpiryNotificationDetailsMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.CRLGenerationInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExtCAMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExternalCRLMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.EntityProfileMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class CAEntityMapperTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CAEntityMapper.class);

    @InjectMocks
    CAEntityMapper caEntityMapper;

    @InjectMocks
    ExtCAMapper extCAMapper;

    @Mock
    EntityProfileMapper entityProfileMapper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    ExternalCRLMapper crlMapper;

    @Mock
    CRLGenerationInfoMapper cRLGenerationInfoMapper;

    @Mock
    CertificateExpiryNotificationDetailsMapper certExpiryNotificationDetailsMapper;

    CAEntityData caEntityData;
    EntityProfileData entityProfileData;

    CAEntityData extCAData;
    ExtCA extCA;

    EntityProfile entityProfile;
    CAEntity caEntity;

    CertificateExpiryNotificationDetails certificateExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
    Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
    Set<CertificateExpiryNotificationDetailsData> certExpiryNotificationDetailsDataSet;
    X509Certificate x509Certificate;
    SetUPData setUPData;

    @Before
    public void setup() throws CertificateException, IOException {
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        caEntity = entitiesSetUpData.getCaEntity();
        caEntityData = entitiesSetUpData.getCaEntityData();

        entityProfile = caEntity.getEntityProfile();
        entityProfileData = caEntityData.getEntityProfileData();

        extCA = entitiesSetUpData.getExtCA();
        extCAData = entitiesSetUpData.getExtCAData();

        certExpiryNotificationDetailsDataSet = caEntityData.getCertificateExpiryNotificationDetailsData();

        setUPData = new SetUPData();

        x509Certificate = setUPData.getX509Certificate("certificates/ENMRootCA.crt");
    }

    @Test
    public void testToAPIModel() throws Exception {

        certificateExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.CRITICAL);
        certificateExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P30D"));
        certificateExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P1D"));
        certificateExpiryNotificationDetailsSet.add(certificateExpiryNotificationDetails);
        when(entityProfileMapper.toAPIFromModel(caEntityData.getEntityProfileData())).thenReturn(entityProfile);
        Mockito.when(certExpiryNotificationDetailsMapper.toAPIFromModel(certExpiryNotificationDetailsDataSet)).thenReturn(certificateExpiryNotificationDetailsSet);
        final CAEntity caentity = caEntityMapper.toAPIFromModel(caEntityData);
        assertEquals(caentity.getCertificateAuthority().getName(), caEntityData.getCertificateAuthorityData().getName());

    }

    @Test(expected = CAEntityNotInternalException.class)
    public void testtoAPIFromModelForCAName() throws Exception {
        CAEntity caentity = caEntityMapper.toAPIFromModelForCAName(caEntityData); 
        caEntityData.setExternalCA(true);
        caentity = caEntityMapper.toAPIFromModelForCAName(caEntityData);
        assertEquals(caentity.getCertificateAuthority().getName(), caEntityData.getCertificateAuthorityData().getName());

    }

    @Test
    public void testFromAPiModel() {
        when(persistenceManager.findEntityByName(EntityProfileData.class, caEntity.getEntityProfile().getName(), "name")).thenReturn(entityProfileData);

        final CAEntityData caEntityData1 = caEntityMapper.fromAPIToModel(caEntity);

        assertEquals(caEntityData1.getCertificateAuthorityData().getName(), caEntity.getCertificateAuthority().getName());
    }

    @Test
    public void testExtCAToAPIModel() throws Exception {
        when(crlMapper.toAPIFromModel(extCAData.getCertificateAuthorityData().getExternalCrlInfoData())).thenReturn(extCA.getExternalCRLInfo());
        final ExtCA extCAMapped = extCAMapper.toAPIFromModel(extCAData);

        assertEquals(extCAData.getCertificateAuthorityData().getName(), extCAMapped.getCertificateAuthority().getName());
        assertEquals(extCAData.getCertificateAuthorityData().getExternalCrlInfoData().getId(), extCAMapped.getExternalCRLInfo().getId());
    }

    @Test
    public void testExtCAFromAPIModel() {
        when(crlMapper.fromAPIToModel(extCA.getExternalCRLInfo())).thenReturn(extCAData.getCertificateAuthorityData().getExternalCrlInfoData());

        final CAEntityData extCADataMapped = extCAMapper.fromAPIToModel(extCA);

        assertEquals(extCA.getCertificateAuthority().getName(), extCADataMapped.getCertificateAuthorityData().getName());
        assertEquals(extCA.getExternalCRLInfo().getId(), extCADataMapped.getCertificateAuthorityData().getExternalCrlInfoData().getId());
    }

    @Test
    public void testExtCAToAPIModelWithExternalCrlInfoNull() throws Exception {
        when(crlMapper.toAPIFromModel(extCAData.getCertificateAuthorityData().getExternalCrlInfoData())).thenReturn(null);
        final ExtCA extCAMapped = extCAMapper.toAPIFromModel(extCAData);

        assertEquals(extCAData.getCertificateAuthorityData().getName(), extCAMapped.getCertificateAuthority().getName());
        assertEquals(null, extCAMapped.getExternalCRLInfo());
    }

    @Test
    public void testExtCAFromAPIModelWithExternalCrlInfoNull() {
        when(crlMapper.toAPIFromModel(extCAData.getCertificateAuthorityData().getExternalCrlInfoData())).thenReturn(null);

        final CAEntityData extCADataMapped = extCAMapper.fromAPIToModel(extCA);

        assertEquals(extCA.getCertificateAuthority().getName(), extCADataMapped.getCertificateAuthorityData().getName());
        assertEquals(null, extCADataMapped.getCertificateAuthorityData().getExternalCrlInfoData());
    }

    @Test
    public void testToAPIFromModelWithoutCertificates() {

        final CAEntity expectedCAEntity = new CAEntity();

        final CertificateAuthority certificateAuthority = extCAMapper.toCertAuthAPIModelWithoutIssuer(caEntityData);
        expectedCAEntity.setCertificateAuthority(certificateAuthority);

        expectedCAEntity.setKeyGenerationAlgorithm(AlgorithmConfigurationModelMapper.fromAlgorithmData(caEntityData.getKeyGenerationAlgorithm()));

        expectedCAEntity.setEntityProfile((EntityProfile) entityProfileMapper.toAPIFromModel(caEntityData.getEntityProfileData()));
        expectedCAEntity.setPublishCertificatetoTDPS(caEntityData.isPublishCertificatetoTDPS());

        assertEquals(expectedCAEntity, extCAMapper.toAPIFromModelWithoutCertificates(caEntityData));
    }

    @Test
    public void testAbstractToObjectModel() throws CertificateEncodingException {
        final Certificate expectedCertificate = new Certificate();

        final CertificateData certificateData = new CertificateData();

        certificateData.setCertificate(x509Certificate.getEncoded());

        certificateData.setIssuerCA(caEntityData);

        expectedCertificate.setId(certificateData.getId());
        expectedCertificate.setSerialNumber(certificateData.getSerialNumber());

        expectedCertificate.setNotBefore(certificateData.getNotBefore());
        expectedCertificate.setNotAfter(certificateData.getNotAfter());
        expectedCertificate.setStatus(CertificateStatus.getStatus(certificateData.getStatus()));
        expectedCertificate.setIssuedTime(certificateData.getIssuedTime());
        expectedCertificate.setSubject(toSubject(certificateData.getSubjectDN()));
        expectedCertificate.setX509Certificate(x509Certificate);

        assertEquals(expectedCertificate, caEntityMapper.toObjectModel(certificateData));
    }

    protected Subject toSubject(final String subjectString) {
        if (!ValidationUtils.isNullOrEmpty(subjectString)) {
            return new Subject().fromASN1String(subjectString);
        }

        return null;
    }
}
