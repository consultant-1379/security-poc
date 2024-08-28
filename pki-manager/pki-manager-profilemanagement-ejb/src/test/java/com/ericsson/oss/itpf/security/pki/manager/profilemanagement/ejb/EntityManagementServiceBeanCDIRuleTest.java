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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.ejb;

import static org.junit.Assert.assertEquals;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.cds.cdi.support.rule.CdiInjectorRule;
import com.ericsson.cds.cdi.support.rule.ImplementationInstance;
import com.ericsson.cds.cdi.support.rule.ObjectUnderTest;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustedEntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class EntityManagementServiceBeanCDIRuleTest {

    @Rule
    public CdiInjectorRule cdiInjectorRule = new CdiInjectorRule(this);

    @Inject
    Logger logger;

    @ImplementationInstance()
    CACertificatePersistenceHelper caCertificatePersistenceHelper = new CACertificatePersistenceHelper() {

        @Override
        public CAEntityData getCAEntity(final String caEntityName) throws CANotFoundException, PersistenceException {
            final CAEntityData caEntityDataPKIRoot = new CAEntityData();
            caEntityDataPKIRoot.setId(1);
            final CertificateAuthorityData certificateAthorityDataPKIRoot = new CertificateAuthorityData();
            certificateAthorityDataPKIRoot.setName("PKI_ROOT");
            certificateAthorityDataPKIRoot.setRootCA(true);
            return caEntityDataPKIRoot;
        }

        @Override
        public List<CertificateData> getCertificateDatas(final String caEntityName, final CertificateStatus... certificateStatuses)
                throws PersistenceException {
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

            final CertificateData certificateDataIntermediate = new CertificateData();
            certificateDataIntermediate.setId(2);
            certificateDataIntermediate.setIssuerCertificate(certificateDataRoot);
            certificateDataIntermediate.setIssuerCA(caEntityDataRoot);
            certificateDataIntermediate.setStatus(CertificateStatus.ACTIVE.getId());
            certificateDataIntermediate.setSerialNumber("67890");
            certificateDataIntermediate.setSubjectDN("CN=ExternalIntermediate, OU=ExtOrgUnit, O=ExtOrg");
            certificateDataIntermediate.setCertificate(cert);


            final CAEntityData caEntityDataIntermediate = new CAEntityData();
            caEntityDataIntermediate.setId(2);
            final CertificateAuthorityData certificateAthorityDataIntermediate = new CertificateAuthorityData();
            certificateAthorityDataIntermediate.setName("EXT_INTERMEDIATE");
            certificateAthorityDataIntermediate.setRootCA(false);
            caEntityDataIntermediate.setCertificateAuthorityData(certificateAthorityDataIntermediate);


            final CertificateData certificateDataPKIRoot = new CertificateData();
            certificateDataPKIRoot.setId(3);
            certificateDataPKIRoot.setIssuerCertificate(certificateDataIntermediate);
            certificateDataPKIRoot.setIssuerCA(caEntityDataIntermediate);
            certificateDataPKIRoot.setStatus(CertificateStatus.ACTIVE.getId());
            certificateDataPKIRoot.setSerialNumber("09876");
            certificateDataPKIRoot.setSubjectDN("CN=PkiRoot, OU=MyOrgUnit, O=MyOrg");
            certificateDataPKIRoot.setPublishedToTDPS(true);
            certificateDataPKIRoot.setCertificate(cert);

            final CAEntityData caEntityDataPKIRoot = new CAEntityData();
            caEntityDataPKIRoot.setId(3);
            final CertificateAuthorityData certificateAthorityDataPKIRoot = new CertificateAuthorityData();
            certificateAthorityDataPKIRoot.setName("PKI_ROOT");
            certificateAthorityDataPKIRoot.setRootCA(true);
            caEntityDataPKIRoot.setCertificateAuthorityData(certificateAthorityDataIntermediate);

            final CertificateData certificateDataRoot2 = new CertificateData();
            certificateDataRoot2.setId(11);
            certificateDataRoot2.setIssuerCertificate(certificateDataRoot2);
            certificateDataRoot2.setStatus(CertificateStatus.INACTIVE.getId());
            certificateDataRoot2.setSerialNumber("123456");
            certificateDataRoot2.setSubjectDN("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg");
            certificateDataRoot2.setIssuerCA(caEntityDataRoot);
            certificateDataRoot2.setCertificate(cert);

            final CertificateData certificateDataIntermediate2 = new CertificateData();
            certificateDataIntermediate2.setId(12);
            certificateDataIntermediate2.setIssuerCertificate(certificateDataRoot2);
            certificateDataIntermediate2.setIssuerCA(caEntityDataRoot);
            certificateDataIntermediate2.setStatus(CertificateStatus.INACTIVE.getId());
            certificateDataIntermediate2.setSerialNumber("678901");
            certificateDataIntermediate2.setSubjectDN("CN=ExternalIntermediate, OU=ExtOrgUnit, O=ExtOrg");
            certificateDataIntermediate2.setCertificate(cert);

            final CertificateData certificateDataPKIRoot2 = new CertificateData();
            certificateDataPKIRoot2.setId(13);
            certificateDataPKIRoot2.setIssuerCertificate(certificateDataIntermediate2);
            certificateDataPKIRoot2.setIssuerCA(caEntityDataIntermediate);
            certificateDataPKIRoot2.setStatus(CertificateStatus.INACTIVE.getId());
            certificateDataPKIRoot2.setSerialNumber("098765");
            certificateDataPKIRoot2.setSubjectDN("CN=PkiRoot, OU=MyOrgUnit, O=MyOrg");
            certificateDataPKIRoot2.setPublishedToTDPS(true);
            certificateDataPKIRoot2.setCertificate(cert);

            for (final CertificateStatus certificateStatus : certificateStatuses) {
                if (CertificateStatus.ACTIVE.equals(certificateStatus)) {
                    certificateDatas.add(certificateDataPKIRoot);
                }
                if (CertificateStatus.INACTIVE.equals(certificateStatus)) {
                    certificateDatas.add(certificateDataPKIRoot2);
                }
            }

            return certificateDatas;
        }
    };

    @ImplementationInstance()
    PKIManagerConfigurationListener pkiManagerConfigurationListener = new PKIManagerConfigurationListener() {

        @Override
        public String getSbLoadBalancerIPv4Address() {
            return "sbLoadBalancerAddress";
        }

        @Override
        public String getSbLoadBalancerIPv6Address() {
            return "sbLoadBalancerIPv6Address";
        }
    };

    @ObjectUnderTest
    EntityManagementServiceBean entityManagementServiceBean;

    @Inject
    SystemRecorder systemRecorder;

    @Test
    public void getTrustedEntityInfosChainByTypeAndNameActiveTest() {

        final CertificateStatus[] certificateStatus = new CertificateStatus[1];
        certificateStatus[0] = CertificateStatus.ACTIVE;
        final List<List<TrustedEntityInfo>> trustedEntityInfosList = entityManagementServiceBean.getTrustedEntitiesInfoChain(EntityType.CA_ENTITY,
                "PKI_ROOT", certificateStatus);

        assertEquals(1, trustedEntityInfosList.size());
        assertEquals(3, trustedEntityInfosList.get(0).size());
        assertEquals("PKI_ROOT", trustedEntityInfosList.get(0).get(0).getEntityName());
        assertEquals("CN=PkiRoot, OU=MyOrgUnit, O=MyOrg", trustedEntityInfosList.get(0).get(0).getSubjectDN());
        assertEquals("CN=ExternalIntermediate, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(0).get(0).getIssuerFullDN());
        assertEquals("EXT_INTERMEDIATE", trustedEntityInfosList.get(0).get(1).getEntityName());
        assertEquals("CN=ExternalIntermediate, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(0).get(1).getSubjectDN());
        assertEquals("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(0).get(1).getIssuerFullDN());
        assertEquals("EXT_ROOT", trustedEntityInfosList.get(0).get(2).getEntityName());
        assertEquals("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(0).get(2).getSubjectDN());
        assertEquals("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(0).get(2).getIssuerFullDN());

    }

    @Test
    public void getTrustedEntityInfosChainByTypeAndNameAllTest() {

        final CertificateStatus[] certificateStatus = new CertificateStatus[2];
        certificateStatus[0] = CertificateStatus.ACTIVE;
        certificateStatus[1] = CertificateStatus.INACTIVE;

        final List<List<TrustedEntityInfo>> trustedEntityInfosList = entityManagementServiceBean.getTrustedEntitiesInfoChain(EntityType.CA_ENTITY,
                "PKI_ROOT", certificateStatus);

        assertEquals(2, trustedEntityInfosList.size());
        assertEquals(3, trustedEntityInfosList.get(0).size());
        assertEquals(3, trustedEntityInfosList.get(1).size());
        assertEquals("PKI_ROOT", trustedEntityInfosList.get(0).get(0).getEntityName());
        assertEquals("CN=PkiRoot, OU=MyOrgUnit, O=MyOrg", trustedEntityInfosList.get(0).get(0).getSubjectDN());
        assertEquals("CN=ExternalIntermediate, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(0).get(0).getIssuerFullDN());
        assertEquals(CertificateStatus.ACTIVE, trustedEntityInfosList.get(0).get(0).getCertificateStatus());
        assertEquals("EXT_INTERMEDIATE", trustedEntityInfosList.get(0).get(1).getEntityName());
        assertEquals("CN=ExternalIntermediate, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(0).get(1).getSubjectDN());
        assertEquals("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(0).get(1).getIssuerFullDN());
        assertEquals(CertificateStatus.ACTIVE, trustedEntityInfosList.get(0).get(1).getCertificateStatus());
        assertEquals("EXT_ROOT", trustedEntityInfosList.get(0).get(2).getEntityName());
        assertEquals("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(0).get(2).getSubjectDN());
        assertEquals("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(0).get(2).getIssuerFullDN());
        assertEquals(CertificateStatus.ACTIVE, trustedEntityInfosList.get(0).get(2).getCertificateStatus());
        assertEquals("PKI_ROOT", trustedEntityInfosList.get(1).get(0).getEntityName());
        assertEquals("CN=PkiRoot, OU=MyOrgUnit, O=MyOrg", trustedEntityInfosList.get(1).get(0).getSubjectDN());
        assertEquals("CN=ExternalIntermediate, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(1).get(0).getIssuerFullDN());
        assertEquals(CertificateStatus.INACTIVE, trustedEntityInfosList.get(1).get(0).getCertificateStatus());
        assertEquals("EXT_INTERMEDIATE", trustedEntityInfosList.get(1).get(1).getEntityName());
        assertEquals("CN=ExternalIntermediate, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(1).get(1).getSubjectDN());
        assertEquals("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(1).get(1).getIssuerFullDN());
        assertEquals(CertificateStatus.INACTIVE, trustedEntityInfosList.get(1).get(1).getCertificateStatus());
        assertEquals("EXT_ROOT", trustedEntityInfosList.get(1).get(2).getEntityName());
        assertEquals("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(1).get(2).getSubjectDN());
        assertEquals("CN=ExternalRoot, OU=ExtOrgUnit, O=ExtOrg", trustedEntityInfosList.get(1).get(2).getIssuerFullDN());
        assertEquals(CertificateStatus.INACTIVE, trustedEntityInfosList.get(1).get(2).getCertificateStatus());
    }
}
