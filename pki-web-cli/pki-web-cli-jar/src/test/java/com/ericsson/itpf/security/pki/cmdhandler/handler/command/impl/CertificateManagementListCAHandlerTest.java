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
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementListCAHandlerTest {

    @InjectMocks
    CertificateManagementListCAHandler certificateManagementListCaHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    CACertificateManagementService caCertificateManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementListCAHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;

    Map<String, Object> properties = new HashMap<String, Object>();
    Certificate certificate = new Certificate();
    List<Certificate> certificates = new ArrayList<Certificate>();
    X509Certificate x509Certificate;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);

        properties.put("command", "CACERTIFICATEMANAGEMENTLIST");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CACERTIFICATEMANAGEMENTLIST);
        command.setProperties(properties);

        final URL url = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");
        String filename = url.getFile();
        filename = URLDecoder.decode(filename);
        x509Certificate = BaseTest.getCertificate(filename);

        certificate.setX509Certificate(x509Certificate);
        final Date currentDate = new Date();
        certificate.setNotBefore(currentDate);
        certificate.setNotAfter(currentDate);
        certificate.setSubject(BaseTest.getSubject("EndEntity"));
        CertificateAuthority issuer = new CertificateAuthority();
        issuer.setSubject(BaseTest.getSubject("IssuerCA"));
        certificate.setIssuer(issuer);
        certificates.add(certificate);
        Mockito.when(eServiceRefProxy.getCaCertificateManagementService()).thenReturn(caCertificateManagementService);

    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.CertificateManagementListCAHandler#Process(com.ericsson.itpf.security.pki.cmdhandler.api.command)} .
     *
     * @throws EntityNotFoundException
     * @throws CertificateGenerationException
     */

    @Test
    public void testProcessCommandCAEntity() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("status", "active");
        Mockito.when(caCertificateManagementService.generateCertificate("ENMROOTCA")).thenReturn(certificate);
        Mockito.when(caCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenReturn(certificates);

        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) certificateManagementListCaHandler.process(command);

        assertEquals(pkiCommandResponse.getAdditionalInformation(), "List of Certificate(s)");

    }

    @Test
    public void testProcessCommandCAEntityStatusRevoked() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("status", "revoked");
        command.setProperties(properties);

        Mockito.when(caCertificateManagementService.generateCertificate("ENMROOTCA")).thenReturn(certificate);
        Mockito.when(caCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.REVOKED)).thenReturn(certificates);

        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) certificateManagementListCaHandler.process(command);

        assertEquals(pkiCommandResponse.getAdditionalInformation(), "List of Certificate(s)");
    }

    @Test
    public void testProcessCommandCAEntityStatusExpired() {

        properties.put("entityname", "ENMROOTCA");
        properties.put("status", "expired");
        command.setProperties(properties);

        Mockito.when(caCertificateManagementService.generateCertificate("ENMROOTCA")).thenReturn(certificate);
        Mockito.when(caCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.EXPIRED)).thenReturn(certificates);

        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) certificateManagementListCaHandler.process(command);

        assertEquals(pkiCommandResponse.getAdditionalInformation(), "List of Certificate(s)");
    }

    @Test
    public void testProcessCommandCANoEntityName() {

        properties.put("status", "active");
        properties.put("entityname", "");
        command.setProperties(properties);

        Mockito.when(caCertificateManagementService.generateCertificate("ENMROOTCA")).thenReturn(certificate);
        Mockito.when(caCertificateManagementService.listCertificates_v1("", CertificateStatus.ACTIVE)).thenReturn(certificates);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY)));
    }

    @Test
    public void testProcessCommandCAEntityNameNull() {

        properties.put("status", "active");
        properties.put("entityname", null);
        command.setProperties(properties);

        Mockito.when(caCertificateManagementService.generateCertificate("ENMROOTCA")).thenReturn(certificate);
        Mockito.when(caCertificateManagementService.listCertificates_v1("", CertificateStatus.ACTIVE)).thenReturn(certificates);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY)));
    }

    @Test
    public void testprocessNoStatus() {
        properties.put("entityname", "ENMROOTCA");
        Mockito.when(caCertificateManagementService.generateCertificate("ENMROOTCA")).thenReturn(certificate);
        Mockito.when(caCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE, CertificateStatus.INACTIVE, CertificateStatus.REVOKED, CertificateStatus.EXPIRED))
                .thenReturn(certificates);
        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) certificateManagementListCaHandler.process(command);
        assertTrue(pkiCommandResponse.getAdditionalInformation().contains(Constants.LIST_OF_CERTIFICATES));
    }

    @Test
    public void testprocessInvalidStatus() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("status", "xyz");
        Mockito.when(caCertificateManagementService.generateCertificate("ENMROOTCA")).thenReturn(certificate);
        Mockito.when(caCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenReturn(certificates);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_STATUS_NOT_SUPPORTED.toInt(), PkiErrorCodes.CERTIFICATE_STATUS_NOT_SUPPORTED)));
    }

    @Test
    public void testProcessCommandCertificateNotFoundException() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("status", "active");
        Mockito.when(caCertificateManagementService.generateCertificate("ENMROOTCA")).thenReturn(certificate);
        Mockito.when(caCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenThrow(new CertificateNotFoundException("Failed Generation"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.NO_CERTIFICATE_FOUND)));
    }

    @Test
    public void testprocessCertificateServiceException() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("status", "active");
        Mockito.when(caCertificateManagementService.generateCertificate("ENMROOTCA")).thenReturn(certificate);
        Mockito.when(caCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenThrow(new CertificateServiceException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));

    }

    @Test
    public void testProcessEntityNotFoundException() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("status", "active");
        Mockito.when(caCertificateManagementService.generateCertificate("ENMROOTCA")).thenReturn(certificate);
        Mockito.when(caCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenThrow(new EntityNotFoundException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ENTITY_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ENTITY_NOT_FOUND)));

    }

    @Test
    public void testProcessCommandCAEntity_SecurityViolationException() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("status", "active");
        Mockito.when(caCertificateManagementService.generateCertificate("ENMROOTCA")).thenReturn(certificate);
        Mockito.when(caCertificateManagementService.listCertificates_v1("ENMROOTCA", CertificateStatus.ACTIVE)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        certificateManagementListCaHandler.process(command);

    }

}
