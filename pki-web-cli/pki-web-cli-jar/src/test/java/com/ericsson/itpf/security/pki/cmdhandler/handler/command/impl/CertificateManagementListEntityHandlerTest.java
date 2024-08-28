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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementListEntityHandlerTest {

    @InjectMocks
    CertificateManagementListEntityHandler certificateManagementListEntityHandler;

    @Mock
    EntityCertificateManagementService endEntityCertificateManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliUtil;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementListEntityHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;

    CertificateRequest certRequest;
    String content = "";

    Map<String, Object> properties = new HashMap<String, Object>();

    Certificate certificate = new Certificate();
    List<Certificate> certificates = new ArrayList<Certificate>();
    X509Certificate x509Certificate;

    /**
     * @throws java.lang.Exception
     */

    @Before
    public void setUp() throws Exception {

        // CSR Generation
        properties.put("command", "ENTITYCERTMANAGEMENTLIST");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYCERTMANAGEMENTLIST);

        final URL url = Thread.currentThread().getContextClassLoader().getResource("CSR.csr");
        String lines = "";
        final BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
        while ((lines = br.readLine()) != null) {
            content += lines + Constants.NEXT_LINE;
        }
        certRequest = BaseTest.generateCertificateRequest(content);

        // Certificate Creation
        final URL url1 = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");
        String filename = url1.getFile();

        final String filePath = URLDecoder.decode(filename);
        final String osAppropriatePath = System.getProperty("os.name").contains("indow") ? filePath.substring(1) : filePath;

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
        Mockito.when(eServiceRefProxy.getEndEntityCertificateManagementService()).thenReturn(endEntityCertificateManagementService);

    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.certificateManagementListEntityHandlerr#Process(com.ericsson.itpf.security.pki.cmdhandler.api.command)} .
     *
     * @throws EntityNotFoundException
     * @throws CertificateGenerationException
     */

    @Test
    public void testProcessCommandEntityActive() {

        properties.put("entityname", "RBS1234");
        properties.put("status", "active");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("RBS1234", CertificateStatus.ACTIVE)).thenReturn(certificates);

        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) certificateManagementListEntityHandler.process(command);

        assertEquals(pkiCommandResponse.getAdditionalInformation(), "List of Certificate(s)");
    }

    @Test
    public void testProcessCommandEntityRevoked() {

        properties.put("entityname", "RBS1234");
        properties.put("status", "revoked");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("RBS1234", CertificateStatus.REVOKED)).thenReturn(certificates);

        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) certificateManagementListEntityHandler.process(command);

        assertEquals(pkiCommandResponse.getAdditionalInformation(), "List of Certificate(s)");
    }

    @Test
    public void testProcessCommandEntityExpired() {

        properties.put("entityname", "RBS1234");
        properties.put("status", "expired");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("RBS1234", CertificateStatus.EXPIRED)).thenReturn(certificates);

        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) certificateManagementListEntityHandler.process(command);

        assertEquals(pkiCommandResponse.getAdditionalInformation(), "List of Certificate(s)");
    }

    @Test
    public void testProcessCommandNullStatus() {

        properties.put("entityname", "RBS1234");
        properties.put("status", " ");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("RBS1234", CertificateStatus.ACTIVE)).thenReturn(certificates);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListEntityHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_STATUS_NOT_SUPPORTED.toInt(), PkiErrorCodes.CERTIFICATE_STATUS_NOT_SUPPORTED)));
    }

    @Test
    public void testProcessCommandNoStatus() throws EntityNotFoundException, CertificateGenerationException {

        properties.put("entityname", "RBS1234");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("RBS1234", CertificateStatus.ACTIVE)).thenReturn(certificates);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListEntityHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.NO_CERTIFICATE_FOUND)));
    }

    @Test
    public void testProcessCommandBlankEntityName() {

        properties.put("entityname", "");
        properties.put("status", "active");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("", CertificateStatus.EXPIRED)).thenReturn(certificates);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListEntityHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY)));
    }

    @Test
    public void testProcessCommandEntityNameNull() {

        properties.put("entityname", null);
        properties.put("status", "active");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("", CertificateStatus.EXPIRED)).thenReturn(certificates);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListEntityHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY)));
    }

    @Test
    public void testProcessCommandNoEntity() throws EntityNotFoundException, CertificateGenerationException {

        properties.put("entityname", null);
        properties.put("status", "active");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1(" ", CertificateStatus.ACTIVE)).thenReturn(certificates);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListEntityHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY)));
    }

    @Test
    public void testProcessCommandCertificateNotFoundException() {

        properties.put("entityname", "RBS1234");
        properties.put("status", "active");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("RBS1234", CertificateStatus.ACTIVE)).thenThrow(new CertificateNotFoundException(""));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.NO_CERTIFICATE_FOUND)));
    }

    @Test
    public void testProcessCertificateServiceException() {

        properties.put("entityname", "RBS1234");
        properties.put("status", "active");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("RBS1234", CertificateStatus.ACTIVE)).thenThrow(new CertificateServiceException(""));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));
    }

    @Test
    public void testProcessCommandEntityNotFoundException() {

        properties.put("entityname", "RBS1234");
        properties.put("status", "active");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("RBS1234", CertificateStatus.ACTIVE)).thenThrow(new EntityNotFoundException(""));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ENTITY_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ENTITY_NOT_FOUND)));
    }

    @Test
    public void testProcessCommandIllegalArgumentException() {

        properties.put("entityname", "RBS1234");
        properties.put("status", "active");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("RBS1234", CertificateStatus.ACTIVE)).thenThrow(new IllegalArgumentException(""));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementListEntityHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_STATUS_NOT_SUPPORTED.toInt(), PkiErrorCodes.CERTIFICATE_STATUS_NOT_SUPPORTED)));
    }

    @Test
    public void testProcessCommandEntityActive_SecurityViolationException() {

        properties.put("entityname", "RBS1234");
        properties.put("status", "active");
        command.setProperties(properties);
        Mockito.when(endEntityCertificateManagementService.listCertificates_v1("RBS1234", CertificateStatus.ACTIVE)).thenThrow(
                new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        certificateManagementListEntityHandler.process(command);

    }
}
