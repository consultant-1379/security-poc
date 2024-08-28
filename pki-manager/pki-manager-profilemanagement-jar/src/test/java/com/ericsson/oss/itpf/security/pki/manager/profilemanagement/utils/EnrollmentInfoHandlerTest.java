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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.PersistenceException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.exception.enrollment.EnrollmentURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.SetUPData;

/**
 * This class is used to test the functionality of getEnrollmentInfo. The test cases include both the success and failure scenarios
 * 
 * @author xbensar
 * 
 */
@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class EnrollmentInfoHandlerTest {

    @InjectMocks
    private EnrollmentInformationHandler enrollmentInformationHandler;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    private PKIManagerConfigurationListener pkiManagerConfigurationListener;

    @Mock
    private Logger logger;

    @Mock
    private ModelMapper caEntityMapper;

    @Mock
    private CACertificatePersistenceHelper caCertificatePersistenceHelper;

    private static Entity entityInput;
    private static EntityInfo entityInfoInput;
    private static EntityProfile entityProfile;
    private static CertificateProfile certificateProfile;

    private static EnrollmentType enrollmentType;

    private static EnrollmentInfo enrollmentInfo;

    private static final String scepEnrollmentURL = "http://localhost:8090/pkira-scep/SUBCA_127";
    private static final String loadBalancerAddress = "localhost";
    private static final String cmpEnrollmentURL = "http://localhost:8091/pkira-cmp/SUBCA_127";
    private static final String trustDistributionURL = "localhost:8080/rootCA_127/profile/12 A9 4H";

    private static Certificate activeCertificate;

    private static CAEntityData caEntityData;
    private static CAEntity caEntity;
    private static CertificateAuthority certificateAuthority;
    private static CertificateData certificateData;
    private static List<CertificateData> certificateDatas = new ArrayList<CertificateData>();
    private static X509Certificate x509Certificate = null;

    private final static String NAME_PATH = "certificateAuthorityData.name";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void setUp() throws CertificateEncodingException, CertificateException, IOException {
        entityInfoInput = new EntityInfo();
        entityInfoInput.setName("ERBS_1");
        caEntity = new CAEntity();
        certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName("SUBCA_127");
        caEntity.setCertificateAuthority(certificateAuthority);
        certificateProfile = new CertificateProfile();
        certificateProfile.setIssuer(caEntity);
        entityProfile = new EntityProfile();
        entityProfile.setCertificateProfile(certificateProfile);
        entityInput = new Entity();
        entityInput.setEntityProfile(entityProfile);
        entityInput.setEntityInfo(entityInfoInput);
        enrollmentType = EnrollmentType.scep;

        caEntityData = new CAEntityData();

        enrollmentInfo = new EnrollmentInfo();

        activeCertificate = new Certificate();

        final SetUPData setUpData = new SetUPData();

        certificateData = setUpData.createCertificateData("t1253D");
        certificateDatas.add(certificateData);
        try {
            x509Certificate = getCertificate();
        } catch (CertificateException e) {
            logger.error("CertificateException caught in EnrollmentInfo");
        } catch (NoSuchProviderException e) {
            logger.error("NoSuchProviderException caught in EnrollmentInfo");
        } catch (IOException e) {
            logger.error("IOException caught in EnrollmentInfo");
        }
        activeCertificate.setX509Certificate(x509Certificate);
        certificateAuthority.setActiveCertificate(activeCertificate);

    }

    @Test
    public void testEnrollmentInfo_Scep_EnrollmentInfo() throws IOException, CertificateException, NoSuchProviderException {
        when(persistenceManager.findEntityByName(CAEntityData.class, entityInput.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName(), NAME_PATH)).thenReturn(
                caEntityData);
        when(caEntityMapper.toAPIFromModel(caEntityData)).thenReturn(caEntity);
        when(pkiManagerConfigurationListener.getScepServiceAddress()).thenReturn(loadBalancerAddress);
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address()).thenReturn(loadBalancerAddress);
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address()).thenReturn(loadBalancerAddress);
        when(caCertificatePersistenceHelper.getActiveCertificate("SUBCA_127")).thenReturn(x509Certificate);

        enrollmentInfo = enrollmentInformationHandler.getEnrollmentInformation(entityInput, enrollmentType);

        assertNotNull(enrollmentInfo);
        assertCertificate(enrollmentInfo.getCaCertificate());
        assertEquals(scepEnrollmentURL, enrollmentInfo.getEnrollmentURL());
        assertEquals(scepEnrollmentURL, enrollmentInfo.getIpv4EnrollmentURL());
        assertEquals(scepEnrollmentURL, enrollmentInfo.getIpv6EnrollmentURL());
        assertEquals(enrollmentInfo.getTrustDistributionPointURL(), trustDistributionURL);

    }

    @Test
    public void testEnrollmentInfo_Cmp_EnrollmentInfo() throws IOException, CertificateException, NoSuchProviderException {
        when(persistenceManager.findEntityByName(CAEntityData.class, entityInput.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName(), NAME_PATH)).thenReturn(
                caEntityData);
        when(caEntityMapper.toAPIFromModel(caEntityData)).thenReturn(caEntity);
        when(pkiManagerConfigurationListener.getCmpServiceAddress()).thenReturn(loadBalancerAddress);
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address()).thenReturn(loadBalancerAddress);
        when(pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address()).thenReturn(loadBalancerAddress);
        when(caCertificatePersistenceHelper.getActiveCertificate("SUBCA_127")).thenReturn(x509Certificate);

        enrollmentType = EnrollmentType.cmp;
        enrollmentInfo = enrollmentInformationHandler.getEnrollmentInformation(entityInput, enrollmentType);
        assertNotNull(enrollmentInfo);
        assertEquals(cmpEnrollmentURL, enrollmentInfo.getEnrollmentURL());
        assertEquals(cmpEnrollmentURL, enrollmentInfo.getIpv4EnrollmentURL());
        assertEquals(cmpEnrollmentURL, enrollmentInfo.getIpv6EnrollmentURL());
        assertEquals(enrollmentInfo.getTrustDistributionPointURL(), trustDistributionURL);

    }

    @Test(expected = EnrollmentURLNotFoundException.class)
    public void testEnrollmentInfo_EnrollmentURLNotFoundException() throws CertificateException, IOException {
        when(caEntityMapper.toAPIFromModel(caEntityData)).thenReturn(caEntity);
        when(pkiManagerConfigurationListener.getCmpServiceAddress()).thenReturn(null);
        when(caCertificatePersistenceHelper.getActiveCertificate("SUBCA_127")).thenReturn(x509Certificate);

        enrollmentType = EnrollmentType.cmp;
        enrollmentInfo = enrollmentInformationHandler.getEnrollmentInformation(entityInput, enrollmentType);
    }

    private X509Certificate getCertificate() throws IOException, CertificateException, NoSuchProviderException {
        final FileInputStream fin = new FileInputStream("src/test/resources/MyRoot.crt");
        final CertificateFactory f = CertificateFactory.getInstance("X.509", "BC");
        final X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
        return certificate;

    }

    private void assertCertificate(final X509Certificate caCertificate) {
        assertEquals(caCertificate.getSerialNumber(), x509Certificate.getSerialNumber());
        assertEquals(caCertificate.getSubjectDN(), x509Certificate.getSubjectDN());
        assertEquals(caCertificate.getIssuerDN(), x509Certificate.getIssuerDN());
    }

    @Test(expected = EntityServiceException.class)
    public void testEnrollmentInfo_EntityServiceException() throws CertificateException, IOException {
        when(caCertificatePersistenceHelper.getActiveCertificate("SUBCA_127")).thenThrow(new CertificateException());

        enrollmentInformationHandler.getEnrollmentInformation(entityInput, enrollmentType);
    }

    @Test(expected = InvalidEntityException.class)
    public void testEnrollmentInfo_PersistenceException() {
        doThrow(new PersistenceException()).when(persistenceManager).findEntityByName(CAEntityData.class,
                entityInput.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName(), NAME_PATH);
        enrollmentInformationHandler.getEnrollmentInformation(entityInput, enrollmentType);
    }
}
