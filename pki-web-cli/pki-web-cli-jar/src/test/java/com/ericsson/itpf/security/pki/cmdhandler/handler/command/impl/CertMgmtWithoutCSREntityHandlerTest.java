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

import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.security.cert.X509Certificate;
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
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

@RunWith(MockitoJUnitRunner.class)
public class CertMgmtWithoutCSREntityHandlerTest {
    private static final String PASSWORD = "secure";
    private static final String ENTITYNAME = "RBS1234";

    @InjectMocks
    CertMgmtWithoutCSREntityHandler certMgmtWithoutCSREntityHandler;

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
    EntityCertificateManagementService entityCertificateManagementService;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertMgmtWithoutCSREntityHandler.class);

    @Mock
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    EServiceRefProxy eServiceRefProxy;


    PkiPropertyCommand command;
    List<String> validCommands;
    List<String> invalidCommands;

    Map<String, Object> properties = new HashMap<String, Object>();

    private static Certificate certificate = new Certificate();

    String content = "";
    List<Certificate> certificates = new ArrayList<Certificate>();
    X509Certificate x509Certificate;
    CertificateChain certificateChain = null;
    KeyStoreInfo keyStoreInfo = null;

    byte[] fileBytes = null;

    @Before
    public void setUp() throws Exception {

        properties.put("command", "ENTITYCERTMANAGEMENTGENARATEWITHOUTCSR");
        properties.put("entityname", "RBS1234");

        final URL url1 = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");

        final String filename = url1.getFile();

        final String filePath = URLDecoder.decode(filename);
        final String osAppropriatePath = System.getProperty("os.name").contains("indow") ? filePath.substring(1) : filePath;
        properties.put("filePath", osAppropriatePath);
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYCERTMANAGEMENTGENARATEWITHOUTCSR);
        command.setProperties(properties);

        x509Certificate = BaseTest.getCertificate(filePath);
        certificate.setX509Certificate(x509Certificate);
        certificates.add(certificate);
        certificateChain = new CertificateChain();
        certificateChain.setCertificateChain(certificates);

        Mockito.doNothing().when(exportedItemsHolder).save(Mockito.anyString(), Mockito.anyObject());
        Mockito.when(eServiceRefProxy.getEntityCertificateManagementService()).thenReturn(entityCertificateManagementService);

    }

    @Test
    public void testProcessCommand_JKS() throws Exception {
        properties.put("format", "JKS");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        fileBytes = filetoBytes("src/test/resources/RBS1234.jks");

        keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAlias("cert");
        keyStoreInfo.setPassword(PASSWORD.toCharArray());
        keyStoreInfo.setKeyStoreFileData(fileBytes);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.JKS)).thenReturn(keyStoreInfo);

        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete(Mockito.anyString())).thenReturn(fileBytes);
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");

        final PkiCommandResponse pkiCommandResponse = certMgmtWithoutCSREntityHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);
    }

    @Test
    public void testProcessCommand_JKS_CertChain() throws Exception {
        properties.put("format", "JKS");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        fileBytes = filetoBytes("src/test/resources/RBS1234.jks");

        keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAlias("cert");
        keyStoreInfo.setPassword(PASSWORD.toCharArray());
        keyStoreInfo.setKeyStoreFileData(fileBytes);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.JKS)).thenReturn(keyStoreInfo);
        Mockito.when(entityCertificateManagementService.getCertificateChain(ENTITYNAME)).thenReturn(certificateChain);
        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete(Mockito.anyString())).thenReturn(fileBytes);
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");

        certMgmtWithoutCSREntityHandler.process(command);
    }

    @Test
    public void testProcessCommand_P12_CertChain() throws Exception {
        properties.put("format", "P12");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        fileBytes = filetoBytes("src/test/resources/RBS1234.p12");

        keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAlias("cert");
        keyStoreInfo.setPassword(PASSWORD.toCharArray());
        keyStoreInfo.setKeyStoreFileData(fileBytes);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenReturn(keyStoreInfo);
        Mockito.when(entityCertificateManagementService.getCertificateChain(ENTITYNAME)).thenReturn(certificateChain);
        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete(Mockito.anyString())).thenReturn(fileBytes);
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.p12");

        certMgmtWithoutCSREntityHandler.process(command);
    }

    @Test
    public void testProcessCommand_P12() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        fileBytes = filetoBytes("src/test/resources/RBS1234.p12");

        keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAlias("cert");
        keyStoreInfo.setPassword(PASSWORD.toCharArray());
        keyStoreInfo.setKeyStoreFileData(fileBytes);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenReturn(keyStoreInfo);

        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete(Mockito.anyString())).thenReturn(fileBytes);
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.p12");

        final PkiCommandResponse pkiCommandResponse = certMgmtWithoutCSREntityHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);
    }

    @Test
    public void testProcessCommand_NullEntity() throws Exception {
        properties.put("entityname", null);
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY)));

    }

    @Test
    public void test_process_AlgorithmNotFoundException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new AlgorithmNotFoundException());

        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION)));
    }

    @Test
    public void test_process_CertificateGenerationException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new CertificateGenerationException());
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.EXCEPTION_IN_CERTIFICATE_GENERATION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION)));

    }

    @Test
    @Ignore
    public void test_process_CANotFoundException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new CANotFoundException());
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CA_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.CA_NOT_FOUND_EXCEPTION)));

    }

    @Test
    public void test_process_CertificateServiceException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new CertificateServiceException());
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains("Suggested Solution :  retry "));

    }

    @Test
    public void test_process_EntityNotFoundException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new EntityNotFoundException());
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ENTITY_NOT_FOUND.toInt(), PkiErrorCodes.ENTITY_DOES_NOT_EXIST)));

    }

    @Test
    public void test_process_InvalidCAException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new InvalidCAException("Invalid CA name"));
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains("Invalid CA name"));

    }

    @Test
    public void test_process_InvalidEntityException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new InvalidEntityException("Invalid CA name"));
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains("Error: 11205 Parameters in the entity are invalid."));

    }

    @Test
    public void test_process_CommandSyntaxException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new CommandSyntaxException());
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.COMMAND_SYNTAX_ERROR.toInt(), PkiErrorCodes.SYNTAX_ERROR)));

    }

    @Test
    public void test_process_IllegalArgumentException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new IllegalArgumentException());
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INVALID_ARGUMENT_ERROR.toInt(), PkiErrorCodes.INVALID_ARGUMENT)));

    }

    @Test
    @Ignore
    public void test_process_InvalidCertificateRequestException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new InvalidCertificateRequestException());
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR)));

    }

    @Test
    public void test_process_ExpiredCertificateException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new ExpiredCertificateException());
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_EXPIRED.toInt(), Constants.EMPTY_STRING)));
    }

    @Test
    public void test_process_RevokedCertificateException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new RevokedCertificateException());
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ISSUER_CERTIFICATE_REVOKED_EXCEPTION.toInt(), Constants.EMPTY_STRING)));

    }

    @Test
    public void testProcessCommand_JKS_SecurityViolationException() throws Exception {
        properties.put("format", "JKS");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        fileBytes = filetoBytes("src/test/resources/RBS1234.jks");

        keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAlias("cert");
        keyStoreInfo.setPassword(PASSWORD.toCharArray());
        keyStoreInfo.setKeyStoreFileData(fileBytes);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.JKS))
                .thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete(Mockito.anyString())).thenReturn(fileBytes);
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");

        certMgmtWithoutCSREntityHandler.process(command);
    }

    @Test
    public void testProcessCommand_JKS_CertChain_SecurityViolationException() throws Exception {
        properties.put("format", "JKS");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        fileBytes = filetoBytes("src/test/resources/RBS1234.jks");

        keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAlias("cert");
        keyStoreInfo.setPassword(PASSWORD.toCharArray());
        keyStoreInfo.setKeyStoreFileData(fileBytes);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.JKS))
                .thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        Mockito.when(entityCertificateManagementService.getCertificateChain(ENTITYNAME)).thenReturn(certificateChain);
        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete(Mockito.anyString())).thenReturn(fileBytes);
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");

        certMgmtWithoutCSREntityHandler.process(command);
    }

    @Test
    public void testProcessCommand_P12_CertChain_SecurityViolationException() throws Exception {
        properties.put("format", "P12");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        fileBytes = filetoBytes("src/test/resources/RBS1234.p12");

        keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAlias("cert");
        keyStoreInfo.setPassword(PASSWORD.toCharArray());
        keyStoreInfo.setKeyStoreFileData(fileBytes);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12))
                .thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        Mockito.when(entityCertificateManagementService.getCertificateChain(ENTITYNAME)).thenReturn(certificateChain);
        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete(Mockito.anyString())).thenReturn(fileBytes);
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.p12");

        certMgmtWithoutCSREntityHandler.process(command);
    }

    @Test
    public void test_process_InvalidEntityAttributeException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new InvalidEntityAttributeException());
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY)));

    }

    @Test
    public void test_process_InvalidCertificateStatusException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12)).thenThrow(new InvalidCertificateStatusException());
        final PkiMessageCommandResponse pkiMessageCommandResponse = (PkiMessageCommandResponse) certMgmtWithoutCSREntityHandler.process(command);
        assertTrue(pkiMessageCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INVALID_CERTIFICATE_STATUS_EXCEPTION.toInt(),Constants.EMPTY_STRING)));

    }

    @Test
    public void testProcessCommand_P12_SecurityViolationException() throws Exception {
        properties.put("format", "P12");
        properties.put("nochain", "noChain");
        properties.put("password", PASSWORD);
        command.setProperties(properties);

        fileBytes = filetoBytes("src/test/resources/RBS1234.p12");

        keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAlias("cert");
        keyStoreInfo.setPassword(PASSWORD.toCharArray());
        keyStoreInfo.setKeyStoreFileData(fileBytes);

        Mockito.when(entityCertificateManagementService.generateCertificate(ENTITYNAME, PASSWORD.toCharArray(), KeyStoreType.PKCS12))
                .thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete(Mockito.anyString())).thenReturn(fileBytes);
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.p12");

        certMgmtWithoutCSREntityHandler.process(command);
    }

    private byte[] filetoBytes(final String filePath) throws IOException {
        FileInputStream fileInputStream = null;

        final File file = new File(filePath);

        final byte[] bFile = new byte[(int) file.length()];

        fileInputStream = new FileInputStream(file);
        fileInputStream.read(bFile);
        fileInputStream.close();

        return bFile;
    }

}
