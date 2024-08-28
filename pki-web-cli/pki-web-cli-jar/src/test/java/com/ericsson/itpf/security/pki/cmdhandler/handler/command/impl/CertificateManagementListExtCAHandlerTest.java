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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiNameMultipleValueAndTableCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.ExtCACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ExtCAManagementService;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementListExtCAHandlerTest {
    @InjectMocks
    CertificateManagementListExtCAHandler certificateManagementListExtCaHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    private ExtCACertificateManagementService extCaCertificateManagementService;

    @Mock
    private ExtCAManagementService extCaManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementImportExtCAHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;

    Map<String, Object> properties = new HashMap<String, Object>();
    X509Certificate x509Certificate;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);

        properties.put("command", "EXTERNALCALIST");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.EXTERNALCALIST);
        //      Certificate Creation
        final URL url1 = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");
        String filename = url1.getFile();
        filename = URLDecoder.decode(filename);
        final String osAppropriatePath = System.getProperty("os.name").contains("indow") ? filename.substring(1) : filename;

        x509Certificate = BaseTest.getCertificate(filename);

        final ExtCA extCA = new ExtCA();
        final CertificateAuthority ca = new CertificateAuthority();
        ca.setName("caName");
        extCA.setCertificateAuthority(ca);

        final List<ExtCA> extCAsList = new ArrayList<ExtCA>();
        extCAsList.add(extCA);
        Mockito.when(extCaManagementService.getExtCAs()).thenReturn(extCAsList);
        Mockito.when(eServiceRefProxy.getExtCaCertificateManagementService()).thenReturn(extCaCertificateManagementService);
        Mockito.when(eServiceRefProxy.getExtCaManagementService()).thenReturn(extCaManagementService);
    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.CertificateManagementListCAHandler#Process(com.ericsson.itpf.security.pki.cmdhandler.api.command)} .
     *
     * @throws IOException
     * @throws CRLException
     * @throws CertificateException
     *
     * @throws EntityNotFoundException
     * @throws CertificateGenerationException
     */

    @Test
    public void testProcessCommandListExtCA() throws CertificateException, CRLException, IOException {
        final List<Certificate> certList = getCertListForTest();

        Mockito.when(extCaCertificateManagementService.listCertificates_v1("caName", CertificateStatus.ACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED, CertificateStatus.INACTIVE))
                .thenReturn(certList);
        final ExtCA extCA = getExtCAForTest();

        Mockito.when(extCaManagementService.getExtCA((ExtCA) Mockito.anyObject())).thenReturn(extCA);
        Mockito.when(extCaManagementService.getTrustProfileByExtCA(Mockito.anyString())).thenReturn(new ArrayList<String>());

        final PkiNameMultipleValueAndTableCommandResponse pkiCommandResponse = (PkiNameMultipleValueAndTableCommandResponse) certificateManagementListExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getMultipleValuesList().get(0).getAdditionalInformation(), Constants.LIST_OF_CERTIFICATES);
        assertEquals(pkiCommandResponse.getMultipleValuesList().size(), 1);
    }

    @Test
    public void testProcessCommandListExtCAWithCAName() throws CertificateException, CRLException, IOException {
        final List<Certificate> certList = getCertListForTest();

        properties.put("name", "caName");
        command.setProperties(properties);

        Mockito.when(extCaCertificateManagementService.listCertificates_v1("caName", CertificateStatus.ACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED, CertificateStatus.INACTIVE))
                .thenReturn(certList);

        final ExtCA extCA = getExtCAForTest();
        final ExtCA extCAAssociate = getExtCAForTest();
        extCAAssociate.getExternalCRLInfo().setNextUpdate(new Date());
        final List<ExtCA> extCAAssociateList = new ArrayList<ExtCA>();
        extCAAssociateList.add(extCAAssociate);
        extCA.setAssociated(extCAAssociateList);

        Mockito.when(extCaManagementService.getExtCA((ExtCA) Mockito.anyObject())).thenReturn(extCA);
        Mockito.when(extCaManagementService.getTrustProfileByExtCA(Mockito.anyString())).thenReturn(new ArrayList<String>());

        final PkiNameMultipleValueAndTableCommandResponse pkiCommandResponse = (PkiNameMultipleValueAndTableCommandResponse) certificateManagementListExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getMultipleValuesList().get(0).getAdditionalInformation(), Constants.LIST_OF_CERTIFICATES);
        assertEquals(pkiCommandResponse.getMultipleValuesList().size(), 2);
        assertEquals(pkiCommandResponse.getMultipleValuesList().get(1).getAdditionalInformation(), Constants.LIST_OF_CRLS);
    }

    @Test
    public void testProcessCommandListExtCA_ExternalCANotFoundException() {
        final List<Certificate> certList = getCertListForTest();
        final Certificate cert = new Certificate();

        Mockito.when(extCaCertificateManagementService.listCertificates_v1("caName", CertificateStatus.ACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED, CertificateStatus.INACTIVE))
                .thenReturn(certList);

        final ExtCA extCA = new ExtCA();
        extCA.setExternalCRLInfo(null);
        Mockito.when(extCaManagementService.getExtCA((ExtCA) Mockito.anyObject())).thenThrow(ExternalCANotFoundException.class);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11501 Invalid argument value"));
    }

    @Test
    public void testProcessCommandListExtCAException1() {
        Mockito.doThrow(new ExternalCredentialMgmtServiceException("Error")).when(extCaCertificateManagementService)
                .listCertificates_v1("caName", CertificateStatus.ACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED, CertificateStatus.INACTIVE);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11002  Internal service error occurred Suggested Solution :  retry"));
    }

    @Test
    public void testProcessCommandListExtCAException2() {
        Mockito.doThrow(new EntityNotFoundException("Error")).when(extCaCertificateManagementService)
                .listCertificates_v1("caName", CertificateStatus.ACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED, CertificateStatus.INACTIVE);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListExtCaHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11501 Invalid argument value:  Error");
    }

    @Test
    public void testProcessCommandListExtCAException3() {
        Mockito.doThrow(new CertificateNotFoundException("Error")).when(extCaCertificateManagementService)
                .listCertificates_v1("caName", CertificateStatus.ACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED, CertificateStatus.INACTIVE);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListExtCaHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11404 Certificate not found for the entity");
    }

    @Test
    public void testProcessCommandListExtCA_CertificateServiceException() {
        Mockito.doThrow(new CertificateServiceException("Error")).when(extCaCertificateManagementService)
                .listCertificates_v1("caName", CertificateStatus.ACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED, CertificateStatus.INACTIVE);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11404 Unable to List Certificates  Internal service error occurred Suggested Solution :  retry"));
    }

    @Test
    public void testProcessCommandListExtCA_EntityNotFoundException() {
        Mockito.doThrow(new EntityNotFoundException("Error")).when(extCaCertificateManagementService)
                .listCertificates_v1("caName", CertificateStatus.ACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED, CertificateStatus.INACTIVE);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListExtCaHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11501 Invalid argument value:  Error");
    }

    @Test
    public void testProcessCommandListExtCA_CertificateNotFoundException() {
        Mockito.doThrow(new CertificateNotFoundException("Error")).when(extCaCertificateManagementService)
                .listCertificates_v1("caName", CertificateStatus.ACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED, CertificateStatus.INACTIVE);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListExtCaHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11404 Certificate not found for the entity");
    }

    @Test
    public void testProcessCommandListExtCA_SecurityViolationException() {
        final List<Certificate> certList = getCertListForTest();

        Mockito.when(extCaCertificateManagementService.listCertificates_v1("caName", CertificateStatus.ACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED, CertificateStatus.INACTIVE))
                .thenReturn(certList);

        Mockito.when(extCaManagementService.getExtCA((ExtCA) Mockito.anyObject())).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        Mockito.when(extCaManagementService.getTrustProfileByExtCA(Mockito.anyString())).thenReturn(new ArrayList<String>());

        certificateManagementListExtCaHandler.process(command);

    }

    /**
     * @return
     * @throws IOException
     * @throws CertificateException
     * @throws CRLException
     */
    public ExtCA getExtCAForTest() throws IOException, CertificateException, CRLException {
        final ExtCA extCA = new ExtCA();
        final URL urlCrl = Thread.currentThread().getContextClassLoader().getResource("testCA.crl");
        String filenameCrl = urlCrl.getFile();
        filenameCrl = URLDecoder.decode(filenameCrl);
        final X509CRL x509CRL = BaseTest.getCRL(filenameCrl);
        final X509CRLHolder x509CRLHolder = new X509CRLHolder(x509CRL);
        final ExternalCRLInfo externalCRLInfo = new ExternalCRLInfo();
        externalCRLInfo.setNextUpdate(new Date(0));
        externalCRLInfo.setX509CRL(x509CRLHolder);
        extCA.setExternalCRLInfo(externalCRLInfo);
        return extCA;
    }

    /**
     * @return
     */
    public List<Certificate> getCertListForTest() {
        final List<Certificate> certList = new ArrayList<Certificate>();
        final Certificate cert = new Certificate();
        cert.setId(1);
        cert.setIssuedTime(new Date());
        cert.setIssuer(null);
        cert.setNotAfter(new Date());
        cert.setNotBefore(new Date());
        cert.setSerialNumber("XXXXXX");
        cert.setStatus(CertificateStatus.ACTIVE);
        cert.setX509Certificate(x509Certificate);
        cert.setSubject(BaseTest.getSubject("ExtInternCA"));
        CertificateAuthority issuer = new CertificateAuthority();
        issuer.setSubject(BaseTest.getSubject("ExtCA"));
        cert.setIssuer(issuer);
        certList.add(cert);
        return certList;
    }

}
