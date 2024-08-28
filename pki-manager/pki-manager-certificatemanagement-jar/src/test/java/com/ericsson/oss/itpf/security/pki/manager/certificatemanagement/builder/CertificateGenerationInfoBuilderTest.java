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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CRLDistributionPoints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.EntitySetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util.AlgorithmCompatibilityValidator;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateGenerationInfoBuilderTest {

    @InjectMocks
    CertificateGenerationInfoBuilder certificateInfoBuilder;

    @Mock
    AlgorithmCompatibilityValidator algorithmCompatibilityValidator;

    @Mock
    private static CAEntityMapper cAEntityMapper;

    @Mock
    PersistenceManager persistenceManager;
    
    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;
    
    @Mock
    PKIManagerConfigurationListener pkiManagerConfigurationListener;

    @Mock
    Logger logger;

    private static SetUPData setUPData;
    private static EntitySetUPData entitySetUPData;

    /**
     * Prepares initial set up required to run the test cases.
     * 
     * @throws Exception
     */
    @BeforeClass
    public static void setUP() {

        setUPData = new SetUPData();
        entitySetUPData = new EntitySetUPData();
    }

    /**
     * Test case for creating CertificateGenerationInfo object for RootCA
     * 
     * @throws Exception
     */
    @Test
    public void testBuild_RootCACertificateInfo() throws Exception {

        final CAEntity rootCAEntity = entitySetUPData.getRootCAEntity();

        final CAEntityData rootCAEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);
        Mockito.when(cAEntityMapper.toAPIFromModel(rootCAEntityData)).thenReturn(rootCAEntity);

        final CertificateGenerationInfo certificateGenerationInfo = certificateInfoBuilder.build(rootCAEntity, RequestType.NEW);

        assertNotNull(certificateGenerationInfo);
        assertEquals(rootCAEntity.getCertificateAuthority().getName(), certificateGenerationInfo.getCAEntityInfo().getName());
        assertEquals(rootCAEntity.getCertificateAuthority().isRootCA(), certificateGenerationInfo.getCAEntityInfo().isRootCA());
        assertEquals(rootCAEntity.getCertificateAuthority().getName(), certificateGenerationInfo.getCAEntityInfo().getName());
        assertEquals(rootCAEntity.getCertificateAuthority().getSubject(), certificateGenerationInfo.getCAEntityInfo().getSubject());

    }

    /**
     * Test case for creating CertificateGenerationInfo object for SubCA
     * 
     * @throws Exception
     */
    
     @Test public void testBuild_SubCACertificateInfo() throws Exception {
     
         final CAEntity subCAEntity = entitySetUPData.getCAEntity();
         final String issuername = subCAEntity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName();

         final CAEntityData rootCAEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, true);
         Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, issuername,
                 Constants.CA_NAME_PATH)).thenReturn(rootCAEntityData);
         final CAEntity rootCAEntity = entitySetUPData.getRootCAEntity();
         Mockito.when(cAEntityMapper.toAPIFromModel(rootCAEntityData)).thenReturn(rootCAEntity);
         X509Certificate rootCertificate = setUPData.createRootCertificate().getX509Certificate();
         Mockito.when(caCertificatePersistenceHelper.getActiveCertificate(issuername)).thenReturn(rootCertificate);
         List<CertificateData> certDataList = new ArrayList<CertificateData>();
         certDataList.add(setUPData.createCertificateData(new Date(), new Date(System.currentTimeMillis() + (10 * 24L * 60L * 60L * 1000L)), new Date(), (rootCertificate.getSerialNumber().toString())));
         Mockito.when(caCertificatePersistenceHelper.getCertificateDatas(issuername, CertificateStatus.ACTIVE)).thenReturn(certDataList);
         Mockito.when(pkiManagerConfigurationListener.getCertificatesRevListDistributionPointServiceIpv4Enable()).thenReturn("true");
         Mockito.when(pkiManagerConfigurationListener.getCertificatesRevListDistributionPointServiceIpv6Enable()).thenReturn("true");
         Mockito.when(pkiManagerConfigurationListener.getCertificatesRevListDistributionPointServiceDnsEnable()).thenReturn("false");
         String ipV4 = "1.1.1.1";
         String ipV6 = "b301:d68:a0b:12e0::1";
         Mockito.when(pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address()).thenReturn(ipV4);
         Mockito.when(pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address()).thenReturn(ipV6);
         
         final CertificateGenerationInfo certificateGenerationInfo = certificateInfoBuilder.build(subCAEntity, RequestType.NEW);

         assertNotNull(certificateGenerationInfo);
         assertEquals(subCAEntity.getCertificateAuthority().getName(), certificateGenerationInfo.getCAEntityInfo().getName());
         assertEquals(subCAEntity.getCertificateAuthority().isRootCA(), certificateGenerationInfo.getCAEntityInfo().isRootCA());
         assertEquals(subCAEntity.getCertificateAuthority().getName(), certificateGenerationInfo.getCAEntityInfo().getName());
         assertEquals(subCAEntity.getCertificateAuthority().getSubject(), certificateGenerationInfo.getCAEntityInfo().getSubject());
         for(CertificateExtension certExtension : certificateGenerationInfo.getCertificateExtensions().getCertificateExtensions()) {
             if(certExtension instanceof CRLDistributionPoints) {
                 CRLDistributionPoints crlDistPoints = (CRLDistributionPoints) certExtension;
                 assertEquals(crlDistPoints.getDistributionPoints().get(0).getDistributionPointName().getFullName().get(0),
                         "http://" + ipV4 + ":8092/pki-cdps?ca_name=" + issuername + "&amp;ca_cert_serialnumber=" + rootCertificate.getSerialNumber().toString());
                 assertEquals(crlDistPoints.getDistributionPoints().get(1).getDistributionPointName().getFullName().get(0),
                         "http://" + ipV6 + ":8092/pki-cdps?ca_name=" + issuername + "&amp;ca_cert_serialnumber=" + rootCertificate.getSerialNumber().toString());
             }
         }
     }
    

    /**
     * Method to test Occurrence of InvalidCAException when CAEntityData is null.
     * 
     * @throws DatatypeConfigurationException
     * @throws IOException
     * @throws CertificateException
     * @{@link InvalidCAException}
     */
    @Test(expected = InvalidCAException.class)
    public void testBuild_SubCACertificateInfo_() throws DatatypeConfigurationException, CertificateException, IOException {

        final CAEntity subCAEntity = entitySetUPData.getCAEntity();
        
        final Certificate certificate = subCAEntity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getActiveCertificate();
        Mockito.when(caCertificatePersistenceHelper.getActiveCertificate(subCAEntity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName())).thenReturn(certificate.getX509Certificate());

        certificateInfoBuilder.build(subCAEntity, RequestType.NEW);

    }

    /**
     * Test case for creating CertificateGenerationInfo object for Entity
     * 
     * @throws Exception
     */
    /*
     * @Test public void testBuild_EntityCertificateInfo() throws Exception {
     * 
     * final Entity entity = entitySetUPData.getEntity(); final String issuername = entity.getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName();
     * 
     * final CAEntityData subCAEntityData = setUPData.createCAEntityData(SetUPData.SUB_CA_NAME, false); Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, issuername,
     * Constants.CA_NAME_PATH)).thenReturn(subCAEntityData); final CAEntity subCAEntity = entitySetUPData.getCAEntity();
     * Mockito.when(cAEntityMapper.toAPIFromModel(subCAEntityData)).thenReturn(subCAEntity); Mockito.when(DateUtility.addDurationToDate(Mockito.any(Date.class),
     * Mockito.any(Duration.class))).thenReturn(entitySetUPData.entityDate);
     * 
     * final CertificateGenerationInfo certificateGenerationInfo = certificateInfoBuilder.build(entity, RequestType.NEW);
     * 
     * assertNotNull(certificateGenerationInfo); assertEquals(entity.getEntityInfo().getName(), certificateGenerationInfo.getEntityInfo().getName()); assertEquals(entity.getEntityInfo().getSubject(),
     * certificateGenerationInfo.getEntityInfo().getSubject()); }
     */

}
