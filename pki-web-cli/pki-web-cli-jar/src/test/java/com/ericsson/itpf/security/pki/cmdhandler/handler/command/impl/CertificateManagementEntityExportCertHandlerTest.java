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
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.util.*;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementEntityExportCertHandlerTest {
    @InjectMocks
    CertificateManagementEntityExportCertHandler certificateManagementEntityExportCertHandler;

    @Mock
    CertificateUtils certUtil;

    @Mock
    CliUtil cliUtil;

    @Mock
    FileUtility fileUtil;

    @Mock
    ExportedItemsHolder exportedItemsHolder;

    @Mock
    EntityCertificateManagementService endEntityCertificateManagementService;

    @Mock
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementEntityExportCertHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;
    Map<String, Object> properties = new HashMap<String, Object>();
    Certificate certificate = new Certificate();
    List<Certificate> certificates = new ArrayList<Certificate>();
    X509Certificate x509Certificate;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYCERTMANAGEMENTEXPORT);
        properties.put("command", "ENTITYCERTMANAGEMENTEXPORT");
        properties.put("entityname", "ENMROOTCA");
        properties.put("format", "f");
        properties.put("password", "pass");
        properties.put("status", "active");
        properties.put("nochain", "noch");
        properties.put("name", "caName");
        command.setProperties(properties);
        //      Certificate Creation
        final URL url1 = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");
        String filename = url1.getFile();

        filename = URLDecoder.decode(filename);
        x509Certificate = BaseTest.getCertificate(filename);
        certificate.setX509Certificate(x509Certificate);
        certificates.add(certificate);

        Mockito.doNothing().when(exportedItemsHolder).save(Mockito.anyString(), Mockito.anyObject());
        Mockito.when(eServiceRefProxy.getEndEntityCertificateManagementService()).thenReturn(endEntityCertificateManagementService);
    }

    @Test
    public void testProcessEntityExportCertHandler() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");
        final PkiCommandResponse pkiCommandResponse = certificateManagementEntityExportCertHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);
    }

    @Test
    public void testProcessEntityExportCertHandler_EntityNull() {
        properties.put("entityname", "");
        command.setProperties(properties);

        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("", CertificateStatus.ACTIVE)).thenThrow(new EntityNotFoundException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementEntityExportCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY)));
    }

    @Test
    public void testProcessEntityExportCertHandler_NoSuchAlgorithmException() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(certUtil.convertCertificates(certificates, "f", "ENMROOTCA", "pass")).thenThrow(new NoSuchAlgorithmException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementEntityExportCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ALGO_NOT_FOUND.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION)));
    }

    @Test
    public void testProcessEntityExportCertHandler_EntityNotFoundException() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(certUtil.convertCertificates(certificates, "f", "ENMROOTCA", "pass")).thenThrow(new EntityNotFoundException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementEntityExportCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.ENTITY_DOES_NOT_EXIST)));
    }

    @Test
    public void testProcessEntityExportCertHandler_AlgorithmNotFoundException() {
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenThrow(new AlgorithmNotFoundException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementEntityExportCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11099"));
    }

    @Test
    public void testProcessEntityExportCertHandler_NoSuchProviderException() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(certUtil.convertCertificates(certificates, "f", "ENMROOTCA", "pass")).thenThrow(new NoSuchProviderException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementEntityExportCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR)));
    }

    @Test
    public void testProcessEntityExportCertHandler_CertificateException() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(certUtil.convertCertificates(certificates, "f", "ENMROOTCA", "pass")).thenThrow(new CertificateException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementEntityExportCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.KEYSTORE_PROCESSING_EXCEPTON)));
    }

    @Test
    public void testProcessEntityExportCertHandler_CertificateNotFoundException() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(certUtil.convertCertificates(certificates, "f", "ENMROOTCA", "pass")).thenThrow(new CertificateNotFoundException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementEntityExportCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.NO_CERTIFICATE_FOUND)));
    }

    @Test
    public void testProcessEntityExportCertHandler_IOException() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(certUtil.convertCertificates(certificates, "f", "ENMROOTCA", "pass")).thenThrow(new IOException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementEntityExportCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.IO_ERROR)));
    }

    @Test
    public void testProcessEntityExportCertHandler_SecurityVioaltionException() throws SecurityViolationException, CommandSyntaxException, CertificateException, KeyStoreException,
            NoSuchProviderException, NoSuchAlgorithmException, IOException {
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenThrow(
                new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        Mockito.when(certUtil.convertCertificates(certificates, "f", "ENMROOTCA", "pass")).thenThrow(new IOException());

        certificateManagementEntityExportCertHandler.process(command);
    }

    @Test
    public void testProcessEntityExportCertHandler_SecurityViolationException() throws SecurityViolationException {
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenThrow(
                new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");
        certificateManagementEntityExportCertHandler.process(command);
    }

    @Test
    public void testProcessEntityExportCertHandler_InvalidCAException() throws Exception {
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(certUtil.convertCertificates(certificates, "f", "ENMROOTCA", "pass")).thenThrow(new InvalidCAException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementEntityExportCertHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11222 Parameters in the entity are invalid."));
    }

    @Test
    public void testProcessEntityExportCertHandler_InvalidCertificateStatusException() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(certUtil.convertCertificates(certificates, "f", "ENMROOTCA", "pass")).thenThrow(new InvalidCertificateStatusException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementEntityExportCertHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11609 "));

    }
}
