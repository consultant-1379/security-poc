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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.ArrayList;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityDetailsPeristenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.tdps.TDPSPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustedEntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntityDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class EntitiesManagerTest {

    @Mock
    Logger logger;

    @InjectMocks
    EntitiesManager entityManager;

    @Mock
    EntityDetailsPeristenceHandler entityDetailsPeristenceHandler;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    TDPSPersistenceHandler tDPSPersistenceHandler;

    @Mock
    PKIManagerConfigurationListener pkiManagerConfigurationListener;

    List<AbstractEntityDetails> entityDetails;

    /**
     * Method to test getEntityDetailsByFilter() method in positive scenario.
     */
    @Test
    public void testgetEntityDetailsByFilter() {

        final EntitiesFilter entitiesFilter = getEntitiesFilter();

        entityDetails = new ArrayList<>();

        when(entityDetailsPeristenceHandler.getEntityDetails(entitiesFilter)).thenReturn(entityDetails);

        final List<AbstractEntityDetails> expectedEntityDetails = entityManager.getEntityDetailsByFilter(entitiesFilter);

        assertNotNull(expectedEntityDetails);

    }

    private EntitiesFilter getEntitiesFilter() {
        final EntitiesFilter entitiesFilter = new EntitiesFilter();

        entitiesFilter.setCertificateAssigned(0);
        entitiesFilter.setId(1);
        entitiesFilter.setLimit(10);
        entitiesFilter.setName("rest%");
        entitiesFilter.setOffset(0);

        final List<EntityType> entityTypes = new ArrayList<EntityType>();

        entityTypes.add(EntityType.CA_ENTITY);
        entitiesFilter.setStatus(getStatusFilter());

        entitiesFilter.setType(entityTypes);
        return entitiesFilter;
    }

    private List<EntityStatus> getStatusFilter() {
        final List<EntityStatus> status = new ArrayList<EntityStatus>();
        return status;
    }

    @Test
    public void getTrustedEntityInfosChainByTypeAndNameActiveTest() throws CertificateException, IOException {
        final List<CertificateData> certificateDatas = new ArrayList<>();
        final CertificateData certificateDataRoot = new CertificateData();
        certificateDataRoot.setId(1);
        certificateDataRoot.setIssuerCertificate(null);
        certificateDataRoot.setStatus(CertificateStatus.ACTIVE.getId());
        certificateDataRoot.setSerialNumber("12345");
        certificateDataRoot.setSubjectDN("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg");
        byte[] cert = Base64.getDecoder().decode(
                "MIIDaDCCAlCgAwIBAgIIYNMsOpXYV1EwDQYJKoZIhvcNAQELBQAwUjEYMBYGA1UEAwwPRU5NX1BLSV9Sb290X0NBMREwDwYDVQQKDAhFUklDU1NPTjEWMBQGA1UECwwNQlVDSV9EVUFDX05BTTELMAkGA1UEBhMCU0UwHhcNMjAxMjI2MTcxNTM4WhcNMzAxMjI2MTcxNTM4WjBSMRgwFgYDVQQDDA9FTk1fUEtJX1Jvb3RfQ0ExETAPBgNVBAoMCEVSSUNTU09OMRYwFAYDVQQLDA1CVUNJX0RVQUNfTkFNMQswCQYDVQQGEwJTRTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIrPq341N/BeQEEaxjijIDg2gHUVDhjFwMiOSfywVu29B4vGUc2A19xo+2AZeSvdVhvzq0sFniU2qTEvu2GwlNtiYz9+VnP2HO6TNP8YLEMCidSQv8O9RskM5xhZYJzA6FzgI3r9FrAi3FdT7HCDJRuNxkTD5UnMMJHJzZ/Vlr5JBvfe097ILa0iRqnYCp4FcQWkyHYMd+GHpchXLa8vn5DLoV+z9/0UFPPuri9Fh+4AJNB8Dm/r0r0ug64wbskVGL8+qhqMPEtFubgDwl6yBJFFf5LurFcoejSIZjCvYZFtfFl5Ezb4v0Nys3rmXWwkS/n3Oy851H/4Ri6BfK+8yw8CAwEAAaNCMEAwHQYDVR0OBBYEFI0L+t5dIJl1c4XuTsWAComC1G06MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQB7UxR7OpOJRlp9XSbp1YjbmRZxhaJHQkzftgg8ll7sfvz/b70t4oBq9XDCAJ9qTDwPW19tMFMZpXV3Br3pfxO2jOs0y8PdDj7/Sj/teTVweRQbFzqKD3vJbi+2wVhGJtsga6r7w0TAd/BePSIVfdOUTU4NVQ9k+M7yQwJoNFn66fwolf+Iog/qPHN0n93oAOreSNmtj0iYmwLP2PG4ntVizJYKsjihoQdm76Efg/uOjiyTsNPfjxrMB5SPT4q+9A1M+jhGj+c6IgfmzUeFM9xET4Nrp/y7VHPpQlAcNrkd29D8GIYVnRWkW7HkAPbtrFGNmLFE/AAVEvxSDkXznS7j");
        Security.addProvider(new BouncyCastleProvider());
        certificateDataRoot.setCertificate(cert);
        final CAEntityData caEntityDataRoot = new CAEntityData();
        caEntityDataRoot.setId(1);
        final CertificateAuthorityData certificateAthorityDataRoot = new CertificateAuthorityData();
        certificateAthorityDataRoot.setName("EXT_ROOT");
        certificateAthorityDataRoot.setRootCA(true);
        certificateAthorityDataRoot.setSubjectDN("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg");
        caEntityDataRoot.setCertificateAuthorityData(certificateAthorityDataRoot);
        certificateDataRoot.setIssuerCA(caEntityDataRoot);
        certificateDataRoot.setPublishedToTDPS(true);
        certificateDatas.add(certificateDataRoot);
        Mockito.when(
                tDPSPersistenceHandler.getCertificateDatas(EntityType.CA_ENTITY, "PKI_ROOT", CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenReturn(certificateDatas);
        Mockito.when(pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address()).thenReturn("10.20.30.40");
        Mockito.when(pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address()).thenReturn("2001:1b70:82a1:103::64:143");
        List<TrustedEntityInfo> trustedEntityInfolist = entityManager.getTrustedEntityInfosByTypeAndName(EntityType.CA_ENTITY, "PKI_ROOT");
        assertEquals("CN=ENM_PKI_Root_CA,O=ERICSSON,OU=BUCI_DUAC_NAM,C=SE",
                trustedEntityInfolist.get(0).getX509Certificate().getIssuerDN().getName());
    }

    @Test(expected = EntityServiceException.class)
    public void getTrustedEntityInfosChainByTypeAndNameActiveTestException() throws CertificateException, IOException {
        final List<CertificateData> certificateDatas = new ArrayList<>();
        final CertificateData certificateDataRoot = new CertificateData();
        certificateDataRoot.setId(1);
        certificateDataRoot.setIssuerCertificate(null);
        certificateDataRoot.setStatus(CertificateStatus.ACTIVE.getId());
        certificateDataRoot.setSerialNumber("12345");
        certificateDataRoot.setSubjectDN("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg");
        certificateDataRoot.setCertificate("dummy".getBytes());
        final CAEntityData caEntityDataRoot = new CAEntityData();
        caEntityDataRoot.setId(1);
        final CertificateAuthorityData certificateAthorityDataRoot = new CertificateAuthorityData();
        certificateAthorityDataRoot.setName("EXT_ROOT");
        certificateAthorityDataRoot.setRootCA(true);
        certificateAthorityDataRoot.setSubjectDN("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg");
        caEntityDataRoot.setCertificateAuthorityData(certificateAthorityDataRoot);
        certificateDataRoot.setIssuerCA(caEntityDataRoot);
        certificateDataRoot.setPublishedToTDPS(true);
        certificateDatas.add(certificateDataRoot);
        Mockito.when(
                tDPSPersistenceHandler.getCertificateDatas(EntityType.CA_ENTITY, "PKI_ROOT", CertificateStatus.ACTIVE, CertificateStatus.INACTIVE))
                .thenReturn(certificateDatas);
        Mockito.when(pkiManagerConfigurationListener.getSbLoadBalancerIPv4Address()).thenReturn("10.20.30.40");
        Mockito.when(pkiManagerConfigurationListener.getSbLoadBalancerIPv6Address()).thenReturn("2001:1b70:82a1:103::64:143");
        List<TrustedEntityInfo> trustedEntityInfolist = entityManager.getTrustedEntityInfosByTypeAndName(EntityType.CA_ENTITY, "PKI_ROOT");
        assertEquals(null, trustedEntityInfolist.get(0).getX509Certificate());
    }
}
