/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.xml.datatype.DatatypeFactory;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.CertificateExpiryNotificationDetailsMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.CRLGenerationInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.CRLInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.EntityProfileMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.AbstractModelMapperv1;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateExpiryNotificationDetailsData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

@RunWith(MockitoJUnitRunner.class)
public class CAEntityModelMapperTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CAEntityMapper.class);

    @InjectMocks
    CAEntityModelMapper caEntityModelMapper;

    @Mock
    EntityProfileMapper entityProfileMapper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CRLInfoMapper crlMapper;

    @Mock
    CRLGenerationInfoMapper cRLGenerationInfoMapper;

    @Mock
    CertificateExpiryNotificationDetailsMapper certExpiryNotificationDetailsMapper;

    @Mock
    AbstractModelMapperv1 abstractModelMapperv1;

    CAEntityData caEntityData;
    EntityProfileData entityProfileData;

    CAEntityData cAEntityData;
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
        cAEntityData = entitiesSetUpData.getExtCAData();

        certExpiryNotificationDetailsDataSet = caEntityData.getCertificateExpiryNotificationDetailsData();

        setUPData = new SetUPData();

        x509Certificate = setUPData.getX509Certificate("certificates/ENMRootCA.crt");
    }

    @Test
    public void testIssuerToAPIFromModel() throws Exception {

        certificateExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.CRITICAL);
        certificateExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P30D"));
        certificateExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P1D"));
        certificateExpiryNotificationDetailsSet.add(certificateExpiryNotificationDetails);
        when(entityProfileMapper.toAPIFromModel(caEntityData.getEntityProfileData())).thenReturn(entityProfile);
        Mockito.when(certExpiryNotificationDetailsMapper.toAPIFromModel(certExpiryNotificationDetailsDataSet))
                .thenReturn(certificateExpiryNotificationDetailsSet);
        assertEquals(caEntity.getCertificateAuthority().getName(), caEntityData.getCertificateAuthorityData().getName());

    }

    @Test
    public void testFromApi() {
        when(persistenceManager.findEntityByName(EntityProfileData.class, caEntity.getEntityProfile().getName(), "name"))
                .thenReturn(entityProfileData);

        final CAEntityData caEntityData1 = caEntityModelMapper.fromApi(caEntity);

        assertEquals(caEntityData1.getCertificateAuthorityData().getName(), caEntity.getCertificateAuthority().getName());
    }

    @Test
    public void testToApi() {
        caEntityData.getCertificateAuthorityData().setIssuer(cAEntityData);
        final CAEntity caEntityLevel0 = caEntityModelMapper.toApi(caEntityData, MappingDepth.LEVEL_0);
        assertEquals(caEntityLevel0.getCertificateAuthority().getName(), cAEntityData.getCertificateAuthorityData().getName());

        final CAEntity caEntityLevel1 = caEntityModelMapper.toApi(caEntityData, MappingDepth.LEVEL_1);
        assertEquals(caEntityLevel1.getCertificateAuthority().getName(), cAEntityData.getCertificateAuthorityData().getName());

        final CAEntity caEntityLevel2 = caEntityModelMapper.toApi(caEntityData, MappingDepth.LEVEL_2);
        assertEquals(caEntityLevel2.getCertificateAuthority().getName(), cAEntityData.getCertificateAuthorityData().getName());
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

        assertEquals(expectedCertificate, caEntityModelMapper.toObjectModel(certificateData));
    }

    protected Subject toSubject(final String subjectString) {
        if (!ValidationUtils.isNullOrEmpty(subjectString)) {
            return new Subject().fromASN1String(subjectString);
        }

        return null;

    }
}
