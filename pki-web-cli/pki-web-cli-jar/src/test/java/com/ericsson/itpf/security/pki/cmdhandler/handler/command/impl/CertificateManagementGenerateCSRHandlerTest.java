/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.*;



import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.util.CertificateUtils;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.CSRManagementService;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CSRExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementGenerateCSRHandlerTest {

    @InjectMocks
    CertificateManagementGenerateCSRHandler certificateManagementGenerateCsrHandler;

    @Mock
    CACertificateManagementService caCertificateManagementService;

    @Mock
    PKCS10CertificationRequestHolder pKCS10CertificationRequestHolder;

    @Mock
    PKCS10CertificationRequest pKCS10CertificationRequest;

    @Mock

    CliUtil cliUtil;

    @Mock
    CertificateUtils certificateUtils;

    @Mock
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Mock
    CSRManagementService csrManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;
    Map<String, Object> properties = new HashMap<String, Object>();
    String content = "CSR Object";
    byte[] fileContents = content.getBytes();
    Certificate certificate = new Certificate();
    X509Certificate x509Certificate;
    List<Certificate> certificates = new ArrayList<Certificate>();

    @Before
    public void setUp() throws Exception {

        properties.put("command", "CERTIFICATEMANAGEMENTGENERATECSR");

        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CERTIFICATEMANAGEMENTGENERATECSR);
        command.setProperties(properties);

        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete("src/test/resources/RBS1234.jks")).thenReturn(fileContents);
        Mockito.when(eServiceRefProxy.getCaCertificateManagementService()).thenReturn(caCertificateManagementService);
        Mockito.when(eServiceRefProxy.getCsrManagementService()).thenReturn(csrManagementService);
    }

    @Test
    public void testProcess_NewKey_As_True() throws IOException {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("newkey", "true");
        command.setProperties(properties);
        Mockito.when(csrManagementService.generateCSR(Mockito.anyString(), Mockito.anyBoolean())).thenReturn(pKCS10CertificationRequestHolder);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest().getEncoded()).thenReturn(fileContents);
        certificateManagementGenerateCsrHandler.process(command);
        Mockito.verify(csrManagementService).generateCSR(Mockito.anyString(), Mockito.anyBoolean());
    }

    @Test
    public void testProcess_NewKey_As_False() throws IOException {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("newkey", "false");
        command.setProperties(properties);
        Mockito.when(csrManagementService.generateCSR(Mockito.anyString(), Mockito.anyBoolean())).thenReturn(pKCS10CertificationRequestHolder);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest().getEncoded()).thenReturn(fileContents);
        certificateManagementGenerateCsrHandler.process(command);
        Mockito.verify(csrManagementService).generateCSR(Mockito.anyString(), Mockito.anyBoolean());

    }

    @Test
    public void testProcess_NewKey_As_True_WithForce() throws IOException {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("newkey", "true");
        properties.put("force", "");
        command.setProperties(properties);
        Mockito.when(csrManagementService.generateCSR(Mockito.anyString(), Mockito.anyBoolean())).thenReturn(pKCS10CertificationRequestHolder);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest().getEncoded()).thenReturn(fileContents);
        certificateManagementGenerateCsrHandler.process(command);
        Mockito.verify(csrManagementService).generateCSR(Mockito.anyString(), Mockito.anyBoolean());
    }

    @Test
    public void testProcess_CANotFoundException() throws IOException {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("newkey", "false");
        command.setProperties(properties);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest().getEncoded()).thenReturn(fileContents);
        Mockito.when(csrManagementService.generateCSR(Mockito.anyString(), Mockito.anyBoolean())).thenThrow(new CANotFoundException());

        final PkiCommandResponse pkiCommandResponse = certificateManagementGenerateCsrHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

    }

    @Test
    public void testProcess_CertificateRequestGenerationException() throws IOException {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("newkey", "false");
        command.setProperties(properties);

        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest().getEncoded()).thenReturn(fileContents);
        Mockito.when(csrManagementService.generateCSR(Mockito.anyString(), Mockito.anyBoolean())).thenThrow(new CertificateRequestGenerationException());

        final PkiCommandResponse pkiCommandResponse = certificateManagementGenerateCsrHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

    }

    @Test
    public void testProcess_CertificateServiceException() throws IOException {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("newkey", "false");
        command.setProperties(properties);

        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest().getEncoded()).thenReturn(fileContents);
        Mockito.when(csrManagementService.generateCSR(Mockito.anyString(), Mockito.anyBoolean())).thenThrow(new CertificateServiceException());

        final PkiCommandResponse pkiCommandResponse = certificateManagementGenerateCsrHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

    }

    @Test
    public void testProcess_InvalidCAException() throws IOException {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("newkey", "false");
        command.setProperties(properties);

        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest().getEncoded()).thenReturn(fileContents);
        Mockito.when(csrManagementService.generateCSR(Mockito.anyString(), Mockito.anyBoolean())).thenThrow(new InvalidCAException());

        final PkiCommandResponse pkiCommandResponse = certificateManagementGenerateCsrHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

    }

    @Test
    public void testProcess_InvalidOperationException() throws IOException {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("newkey", "false");
        command.setProperties(properties);

        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest().getEncoded()).thenReturn(fileContents);
        Mockito.when(csrManagementService.generateCSR(Mockito.anyString(), Mockito.anyBoolean())).thenThrow(new InvalidOperationException());

        final PkiCommandResponse pkiCommandResponse = certificateManagementGenerateCsrHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

    }

    @Test
    public void testProcess_KeyPairGenerationException() throws IOException {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("newkey", "false");
        command.setProperties(properties);

        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest().getEncoded()).thenReturn(fileContents);
        Mockito.when(csrManagementService.generateCSR(Mockito.anyString(), Mockito.anyBoolean())).thenThrow(new KeyPairGenerationException());

        final PkiCommandResponse pkiCommandResponse = certificateManagementGenerateCsrHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

    }

    @Test
    public void testProcess_SecurityViolationException() throws SecurityViolationException, IOException {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("newkey", "true");
        command.setProperties(properties);
        Mockito.when(csrManagementService.generateCSR(Mockito.anyString(), Mockito.anyBoolean()))
                .thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest()).thenReturn(pKCS10CertificationRequest);
        Mockito.when(pKCS10CertificationRequestHolder.getCertificateRequest().getEncoded()).thenReturn(fileContents);
        certificateManagementGenerateCsrHandler.process(command);
        Mockito.verify(csrManagementService).generateCSR(Mockito.anyString(), Mockito.anyBoolean());
    }
}
