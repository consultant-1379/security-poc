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

import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.security.*;
import java.security.cert.*;
import java.util.*;



import org.junit.*;
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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.*;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementGenerateEntityHandlerTest {

    @InjectMocks
    CertificateManagementGenerateEntityHandler certificateManagementGenerateEntityHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    FileUtility fileUtil;

    @Mock
    CertificateUtils certUtil;

    @Mock
    ExportedItemsHolder exportedItemsHolder;

    @Mock
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Mock
    EntityCertificateManagementService entityCertificateManagementService;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementGenerateEntityHandler.class);

    PkiPropertyCommand command;
    List<String> validCommands;
    List<String> invalidCommands;

    Map<String, Object> properties = new HashMap<String, Object>();

    private static Certificate certificate = new Certificate();

    CertificateRequest certRequest;
    String content = "";
    List<Certificate> certificates = new ArrayList<Certificate>();
    CertificateChain certificateChain = new CertificateChain();
    X509Certificate x509Certificate;

    /**
     * @throws java.lang.Exception
     */

    @Before
    public void setUp() throws Exception {

        properties.put("command", "ENTITYCERTMANAGEMENTGENARATE");
        properties.put("entityname", "RBS1234");

        final URL url = Thread.currentThread().getContextClassLoader().getResource("CSR.csr");
        final URL url1 = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");

        final String filename = url1.getFile();

        final String filePath = URLDecoder.decode(filename);
        final String osAppropriatePath = System.getProperty("os.name").contains("indow") ? filePath.substring(1) : filePath;
        properties.put("filePath", osAppropriatePath);
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYCERTMANAGEMENTGENARATE);
        command.setProperties(properties);

        String lines = "";

        final BufferedReader br = new BufferedReader(new InputStreamReader(url.openStream()));
        while ((lines = br.readLine()) != null) {
            content += lines + Constants.NEXT_LINE;
        }
        certRequest = BaseTest.generateCertificateRequest(content);
        Mockito.when(cliUtil.getFileContentFromCommandProperties(properties)).thenReturn(content);
        x509Certificate = BaseTest.getCertificate(filePath);
        certificate.setX509Certificate(x509Certificate);
        certificates.add(certificate);

        certificateChain.setCertificateChain(certificates);
        Mockito.doNothing().when(exportedItemsHolder).save(Mockito.anyString(), Mockito.anyObject());
        Mockito.when(eServiceRefProxy.getEntityCertificateManagementService()).thenReturn(entityCertificateManagementService);

    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.CertificateManagementGenerateEntityHandler#Process(com.ericsson.itpf.security.pki.cmdhandler.api.command)}
     * .
     *
     * @throws EntityNotFoundException
     * @throws CertificateGenerationException
     */

    @Test
    public void testProcessCommand() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        properties.put("format", "f");
        properties.put("nochain", "noChain");
        properties.put("password", "pass");
        command.setProperties(properties);
        final byte[] fileContents = content.getBytes();
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");
        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete("")).thenReturn(fileContents);
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenReturn(certificate);
        Mockito.when(certUtil.convertCertificates(certificates, "f", "RBS1234", "pass")).thenReturn("");

        final PkiCommandResponse pkiCommandResponse = certificateManagementGenerateEntityHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);

    }

    @Test
    public void testProcessCommand_Nopopup() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        properties.put("nopopup", "");
        command.setProperties(properties);
        final byte[] fileContents = content.getBytes();
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");
        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete("")).thenReturn(fileContents);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Certificate Generated Successfully for"));

    }

    @Test
    public void testProcessCommand_JKS() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        properties.put("format", "JKS");
        properties.put("password", "pass");
        command.setProperties(properties);
        final byte[] fileContents = content.getBytes();
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");
        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete("")).thenReturn(fileContents);
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenReturn(certificate);

        Mockito.when(entityCertificateManagementService.getCertificateChain("RBS1234")).thenReturn(certificateChain);
        Mockito.when(certUtil.convertCertificates(certificates, "f", "RBS1234", "pass")).thenReturn("");

        final PkiCommandResponse pkiCommandResponse = certificateManagementGenerateEntityHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);

    }

    @Test
    public void testProcessCommand_P12() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        properties.put("format", "P12");
        properties.put("password", "pass");
        command.setProperties(properties);
        final byte[] fileContents = content.getBytes();
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");
        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete("")).thenReturn(fileContents);
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenReturn(certificate);

        Mockito.when(entityCertificateManagementService.getCertificateChain("RBS1234")).thenReturn(certificateChain);
        Mockito.when(certUtil.convertCertificates(certificates, "f", "RBS1234", "pass")).thenReturn("");

        final PkiCommandResponse pkiCommandResponse = certificateManagementGenerateEntityHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);

    }

    @Test
    public void testProcessCommandEntityNameNull() {
        properties.put("entityname", "");
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(" ", certRequest)).thenReturn(null);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY)));

    }

    @Test
    public void testAlgorithmNotFoundException() {
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenThrow(new AlgorithmNotFoundException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION)));
    }

    @Test
    @Ignore
    public void testCANotFoundException() {
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenThrow(new CANotFoundException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CA_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.CA_NOT_FOUND_EXCEPTION)));
    }

    @Test
    public void testCertificateGenerationException() {
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenThrow(new CertificateGenerationException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.EXCEPTION_IN_CERTIFICATE_GENERATION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION)));

    }

    @Test
    public void testCertificateServiceException() {
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenThrow(new CertificateServiceException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));

    }

    @Test
    public void testInvalidCAException() {
        final InvalidCAException invalidCAException = new InvalidCAException();
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenThrow(new InvalidCAException("Invalid CA Name"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Invalid CA Name"));

    }

    @Test
    public void testInvalidCertificateRequestException() {
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenThrow(new InvalidCertificateRequestException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INVALID_CERTIFICATE_REQUEST_EXCEPTION.toInt(), PkiErrorCodes.INVALID_CERTIFICATE_REQUEST)));

    }

    @Test
    public void testProcessInvalidEntityException() {

        final InvalidEntityException invalidEntityException = new InvalidEntityException("invalid entity");
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenThrow(invalidEntityException);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), invalidEntityException.getMessage())));

    }

    @Test
    public void testProcess_CommandSyntaxException() {
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenThrow(new CommandSyntaxException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.COMMAND_SYNTAX_ERROR.toInt(), PkiErrorCodes.SYNTAX_ERROR)));

    }

    @Test
    public void testProcess_EntityNotFoundException() {
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenThrow(new EntityNotFoundException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.ENTITY_DOES_NOT_EXIST)));

    }

    @Test
    @Ignore
    public void testProcess_CertificateNotFoundException() {
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenThrow(new CertificateNotFoundException(content));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_NOT_FOUND.toInt(), PkiErrorCodes.NO_CERTIFICATE_FOUND)));

    }

    @Test
    @Ignore
    public void testProcess_CANotFoundException() {
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenThrow(new CANotFoundException(content));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateEntityHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CA_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.CA_NOT_FOUND_EXCEPTION)));

    }

    @Test
    public void testProcessCommand_NoSuchAlgorithmException() throws Exception {
        properties.put("format", "P12");
        properties.put("password", "pass");
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenReturn(certificate);
        Mockito.when(entityCertificateManagementService.getCertificateChain("RBS1234")).thenReturn(certificateChain);
        Mockito.when(certUtil.convertCertificates(Mockito.anyList(), Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenThrow(NoSuchAlgorithmException.class);

        certificateManagementGenerateEntityHandler.process(command);
    }

    @Test
    public void testProcessCommandNoSuchProviderException() throws Exception {
        properties.put("format", "P12");
        properties.put("password", "pass");
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenReturn(certificate);
        Mockito.when(entityCertificateManagementService.getCertificateChain("RBS1234")).thenReturn(certificateChain);
        Mockito.when(certUtil.convertCertificates(Mockito.anyList(), Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenThrow(NoSuchProviderException.class);

        certificateManagementGenerateEntityHandler.process(command);
    }

    @Test
    public void testProcessCommandKeyStoreException() throws Exception {
        properties.put("format", "P12");
        properties.put("password", "pass");
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenReturn(certificate);
        Mockito.when(entityCertificateManagementService.getCertificateChain("RBS1234")).thenReturn(certificateChain);
        Mockito.when(certUtil.convertCertificates(Mockito.anyList(), Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenThrow(KeyStoreException.class);

        certificateManagementGenerateEntityHandler.process(command);
    }

    @Test
    public void testProcessCommandCertificateEncodingException() throws Exception {
        properties.put("format", "P12");
        properties.put("password", "pass");
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenReturn(certificate);
        Mockito.when(entityCertificateManagementService.getCertificateChain("RBS1234")).thenReturn(certificateChain);
        Mockito.when(certUtil.convertCertificates(Mockito.anyList(), Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenThrow(CertificateEncodingException.class);

        certificateManagementGenerateEntityHandler.process(command);
    }

    @Test
    public void testProcessCommandExpiredCertificateException() throws Exception {
        properties.put("format", "P12");
        properties.put("password", "pass");
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenReturn(certificate);
        Mockito.when(entityCertificateManagementService.getCertificateChain("RBS1234")).thenReturn(certificateChain);
        Mockito.when(certUtil.convertCertificates(Mockito.anyList(), Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenThrow(ExpiredCertificateException.class);

        certificateManagementGenerateEntityHandler.process(command);
    }

    @Test
    public void testProcessCommandRevokedCertificateException() throws Exception {
        properties.put("format", "P12");
        properties.put("password", "pass");
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenReturn(certificate);
        Mockito.when(entityCertificateManagementService.getCertificateChain("RBS1234")).thenReturn(certificateChain);
        Mockito.when(certUtil.convertCertificates(Mockito.anyList(), Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenThrow(RevokedCertificateException.class);

        certificateManagementGenerateEntityHandler.process(command);
    }

    @Test
    public void testProcessCommandIOException() throws Exception {
        properties.put("format", "P12");
        properties.put("password", "pass");
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenReturn(certificate);
        Mockito.when(entityCertificateManagementService.getCertificateChain("RBS1234")).thenReturn(certificateChain);
        Mockito.when(certUtil.convertCertificates(Mockito.anyList(), Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenThrow(IOException.class);

        certificateManagementGenerateEntityHandler.process(command);
    }

    @Test
    public void testProcessCommandException() throws Exception {
        properties.put("format", "P12");
        properties.put("password", "pass");
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenReturn(certificate);
        Mockito.when(entityCertificateManagementService.getCertificateChain("RBS1234")).thenReturn(certificateChain);
        Mockito.when(certUtil.convertCertificates(Mockito.anyList(), Mockito.anyString(), Mockito.anyString(), Mockito.anyString())).thenThrow(Exception.class);

        certificateManagementGenerateEntityHandler.process(command);
    }

    @Test
    public void testProcessCommand_SecurityViolationException()
            throws SecurityViolationException, CommandSyntaxException, CertificateException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, IOException {
        properties.put("format", "f");
        properties.put("nochain", "noChain");
        properties.put("password", "pass");
        command.setProperties(properties);
        final byte[] fileContents = content.getBytes();
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");
        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete("")).thenReturn(fileContents);
        Mockito.when(entityCertificateManagementService.generateCertificate("RBS1234", certRequest)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        Mockito.when(certUtil.convertCertificates(certificates, "f", "RBS1234", "pass")).thenReturn("");

        certificateManagementGenerateEntityHandler.process(command);

    }
}
