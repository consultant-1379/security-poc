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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.cert.*;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CRLInfoMapper;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.utils.DateUtil;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.builder.RevokedCertificatesInfoBuilder;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.CRLSetUpData;

/**
 * Test Class for CrlV2Generator.
 */
@RunWith(MockitoJUnitRunner.class)
public class CrlV2GeneratorTest {
    final String BC = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

    @InjectMocks
    CrlV2Generator crlV2Generator;

    @Mock
    DateUtil dateUtil;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    RevokedCertificatesInfoBuilder revokedCertificatesInfoBuilder;

    @Mock
    CRLInfoMapper cRLInfoMapper;

    @Mock
    Logger logger;

    @Mock
    X509CRLBuilder x509CRLBuilder;

    @Mock
    CertificateAuthorityModelMapper certificateAuthorityModelMapper;
    
    @Mock
    private SystemRecorder systemRecorder;

    private static CertificateAuthority certificateAuthority;
    private static Certificate issuerCertificate;;
    private static CrlGenerationInfo crlGenerationInfo;
    private static List<RevokedCertificatesInfo> revokedCertificatesInfoList;
    private static CRLNumber cRLNumber;
    private static X509CRL x509CRL;

    /**
     * Prepares initial Data.
     * 
     * @throws IOException
     * @throws CRLException
     * @throws CertificateException
     */
    @Before
    public void SetUpData() throws CertificateException, CRLException, IOException {
        certificateAuthority = CRLSetUpData.getCertificateAuthorityForX509(null);
        issuerCertificate = CRLSetUpData.getCertificate();
        crlGenerationInfo = CRLSetUpData.getCrlGenerationInfo();

        revokedCertificatesInfoList = CRLSetUpData.getRevokedCertificatesInfoList();
        cRLNumber = new CRLNumber();
        cRLNumber.setSerialNumber(1);
        cRLNumber.setCritical(true);
        crlGenerationInfo.getCrlExtensions().setCrlNumber(cRLNumber);
        x509CRL = CRLSetUpData.getX509CRL("src/test/resources/test1_123.crl");
    }

    /**
     * Method to test generateCRL.
     */
    @Test
    public void testGenerateCRL_When_CrlInfosNull() {
        Mockito.when(revokedCertificatesInfoBuilder.buildRevokedCertificateInfo(issuerCertificate)).thenReturn(revokedCertificatesInfoList);
        Mockito.when(x509CRLBuilder.build(certificateAuthority, issuerCertificate, revokedCertificatesInfoList, crlGenerationInfo, cRLNumber)).thenReturn(x509CRL);
        CRLInfo ExpectedCrlInfo = crlV2Generator.generateCRL(certificateAuthority, issuerCertificate, crlGenerationInfo);
        assertNotNull(ExpectedCrlInfo);
        assertEquals(0, ExpectedCrlInfo.getId());
        assertEquals(CRLStatus.LATEST, ExpectedCrlInfo.getStatus());
    }

    /**
     * Method to test generateCRL.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testGenerateCRL() {
        Mockito.when(revokedCertificatesInfoBuilder.buildRevokedCertificateInfo(issuerCertificate)).thenReturn(revokedCertificatesInfoList);
        Mockito.when(
                x509CRLBuilder.build((CertificateAuthority) Mockito.anyObject(), (Certificate) Mockito.anyObject(), Mockito.anyList(), (CrlGenerationInfo) Mockito.anyObject(),
                        (CRLNumber) Mockito.anyObject())).thenReturn(x509CRL);
        CRLInfo ExpectedCrlInfo = crlV2Generator.generateCRL(CRLSetUpData.getCertificateAuthorityForX509(CRLSetUpData.getCRLInfo("LATEST")), issuerCertificate, crlGenerationInfo);
        assertNotNull(ExpectedCrlInfo);
        assertEquals(0, ExpectedCrlInfo.getId());
        assertEquals(CRLStatus.LATEST, ExpectedCrlInfo.getStatus());
    }

}
