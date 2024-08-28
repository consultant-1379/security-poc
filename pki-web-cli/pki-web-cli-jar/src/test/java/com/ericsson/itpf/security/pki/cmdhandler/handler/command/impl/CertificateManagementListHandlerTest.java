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
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.net.URLDecoder;
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
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CertificateInfo;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementListHandlerTest {

    @InjectMocks
    CertificateManagementListHandler certificateManagementListHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    CACertificateManagementService caCertificateManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementListHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;

    Map<String, Object> properties = new HashMap<String, Object>();
    Certificate certificate = new Certificate();
    CertificateInfo certificateInfo = new CertificateInfo();
    List<CertificateInfo> certificates = new ArrayList<CertificateInfo>();
    X509Certificate x509Certificate;

    List<String> statusList = new ArrayList<String>();

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);

        properties.put("command", "CERTIFICATEMANAGEMENTLIST");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CERTIFICATEMANAGEMENTLIST);
        command.setProperties(properties);

        final URL url = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");
        String filename = url.getFile();
        filename = URLDecoder.decode(filename);
        x509Certificate = BaseTest.getCertificate(filename);
        certificate.setX509Certificate(x509Certificate);
        final Date currentDate = new Date();
        certificate.setNotBefore(currentDate);
        certificate.setNotAfter(currentDate);
        certificateInfo.setEntityName(certificate.getX509Certificate().getSubjectDN().getName());
        certificateInfo.setNotAfter(certificate.getNotAfter());
        certificateInfo.setNotBefore(certificate.getNotBefore());
        certificateInfo.setSerialNumber(certificate.getX509Certificate().getSerialNumber().toString());
        certificateInfo.setStatus(certificate.getStatus());
        certificateInfo.setSubject(new Subject().fromASN1String("CN=MyRoot"));
        certificateInfo.setSubjectAltName(certificateInfo.getSubjectAltName());
        certificates.add(certificateInfo);
        Mockito.when(eServiceRefProxy.getCaCertificateManagementService()).thenReturn(caCertificateManagementService);

    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.CertificateManagementListHandler#Process(com.ericsson.itpf.security.pki.cmdhandler.api.command)} .
     *
     * @throws EntityNotFoundException
     * @throws CertificateGenerationException
     */

    @Test
    public void testProcessCommand_withoutStatus() {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("serialno", "453097e2080f5ec8");
        command.setProperties(properties);
        Mockito.when(caCertificateManagementService.listIssuedCertificates((CACertificateIdentifier) Mockito.anyObject(), (CertificateStatus[]) Mockito.any())).thenReturn(certificates);

        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) certificateManagementListHandler.process(command);

        assertEquals(pkiCommandResponse.getAdditionalInformation(), "List of Certificate(s)");
    }

    @Test
    public void testProcessCommand_withStatus() {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("serialno", "453097e2080f5ec8");
        properties.put("status", "active");
        statusList.add("active");
        command.setProperties(properties);

        Mockito.when(commandHandlerUtils.getCertificateStatus("")).thenReturn(null);
        Mockito.when(cliUtil.splitBySeparator("active", ",")).thenReturn(statusList);
        Mockito.when(cliUtil.removeFirstAndLastChar("active")).thenReturn("active");

        Mockito.when(caCertificateManagementService.listIssuedCertificates((CACertificateIdentifier) Mockito.anyObject(), (CertificateStatus[]) Mockito.any())).thenReturn(certificates);

        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) certificateManagementListHandler.process(command);

        assertEquals(pkiCommandResponse.getAdditionalInformation(), "List of Certificate(s)");
    }

    @Test
    public void testProcessCommandCANoEntityName() {

        properties.put("serialno", "lkijhyt");
        properties.put("caentityname", "");
        command.setProperties(properties);

        Mockito.when(caCertificateManagementService.listIssuedCertificates((CACertificateIdentifier) Mockito.anyObject(), (CertificateStatus[]) Mockito.any())).thenReturn(certificates);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY)));
    }

    @Test
    public void testProcessCommandCertificateSerialNumberNull() {

        properties.put("serialno", "");
        properties.put("caentityname", "ENMROOTCA");
        command.setProperties(properties);

        Mockito.when(caCertificateManagementService.listIssuedCertificates((CACertificateIdentifier) Mockito.anyObject(), (CertificateStatus[]) Mockito.any())).thenReturn(certificates);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.CERTIFICATE_SERIAL_NO_CANNOT_BE_NULL_OR_EMPTY)));
    }

    @Test
    public void testProcessCommandCAEntityNameNull() {

        properties.put("serialno", "lkijhyt");
        properties.put("caentityname", null);
        command.setProperties(properties);

        Mockito.when(caCertificateManagementService.listIssuedCertificates((CACertificateIdentifier) Mockito.anyObject(), (CertificateStatus[]) Mockito.any())).thenReturn(certificates);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY)));
    }

    @Test
    public void testProcessInvalidStatus() {
        properties.put("serialno", "lkijhyt");
        properties.put("caentityname", "ENMROOTCA");
        properties.put("status", "invalid");
        statusList.add("invalid");
        command.setProperties(properties);

        Mockito.when(commandHandlerUtils.getCertificateStatus("")).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(cliUtil.splitBySeparator("invalid", ",")).thenReturn(statusList);
        Mockito.when(cliUtil.removeFirstAndLastChar("invalid")).thenReturn("invalid");

        Mockito.when(caCertificateManagementService.listIssuedCertificates((CACertificateIdentifier) Mockito.anyObject(), (CertificateStatus[]) Mockito.any()))
                .thenThrow(new IllegalArgumentException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_STATUS_NOT_SUPPORTED.toInt(), Constants.EMPTY_STRING)));
    }

    @Test
    public void testProcessCommandCertificateNotFoundException() {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("serialno", "453097e2080f5ec8");
        command.setProperties(properties);
        Mockito.when(caCertificateManagementService.listIssuedCertificates((CACertificateIdentifier) Mockito.anyObject(), (CertificateStatus[]) Mockito.any()))
                .thenThrow(new CertificateNotFoundException("Failed Generation"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.NO_CERTIFICATE_FOUND)));

    }

    @Test
    public void testProcessCertificateServiceException() {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("serialno", "453097e2080f5ec8");
        command.setProperties(properties);
        Mockito.when(caCertificateManagementService.listIssuedCertificates((CACertificateIdentifier) Mockito.anyObject(), (CertificateStatus[]) Mockito.any()))
                .thenThrow(new CertificateServiceException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));

    }

    @Test
    public void testProcessCANotFoundException() {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("serialno", "453097e2080f5ec8");
        command.setProperties(properties);
        Mockito.when(caCertificateManagementService.listIssuedCertificates((CACertificateIdentifier) Mockito.anyObject(), (CertificateStatus[]) Mockito.any())).thenThrow(new CANotFoundException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ENTITY_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.CERTIFICATE_LISTING_FAILED)));

    }

    @Test
    public void testProcessCommand_SecurityViolationException() {
        properties.put("caentityname", "ENMROOTCA");
        properties.put("serialno", "453097e2080f5ec8");
        command.setProperties(properties);
        Mockito.when(caCertificateManagementService.listIssuedCertificates((CACertificateIdentifier) Mockito.anyObject(), (CertificateStatus[]) Mockito.any()))
                .thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        certificateManagementListHandler.process(command);

    }

}
