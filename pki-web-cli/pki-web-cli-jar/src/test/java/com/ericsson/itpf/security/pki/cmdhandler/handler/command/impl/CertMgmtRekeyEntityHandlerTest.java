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

import java.io.*;
import java.net.URL;
import java.net.URLDecoder;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;


@RunWith(MockitoJUnitRunner.class)
public class CertMgmtRekeyEntityHandlerTest {
    private static final String ENTITYNAME = "entityname";
    private static final String ENTITY = "RBS1234";
    private static final String PASSWORD = "password";
    private static final String PASSWORD_VALUE = "secure";
    private static final String FORMAT = "format";
    private static final String JKS = "JKS";
    private static final String P12 = "P12";
    private static final String JKSFILEPATH = "src/test/resources/RBS1234.jks";
    private static final String P12FILEPATH = "src/test/resources/RBS1234.p12";

    @InjectMocks
    CertMgmtRekeyEntityHandler certMgmtRekeyEntityHandler;

    @Mock
    CertMgmtUpdateEntityCommonHandler certMgmtUpdateEntityCommonHandler;

    @Mock
    CliUtil cliUtil;

    @Mock
    EntityCertificateManagementService entityCertificateManagementService;

    @Spy
    Logger logger = LoggerFactory.getLogger(CertMgmtRekeyEntityHandler.class);

    @Mock
    ExportedItemsHolder exportedItemsHolder;

    @Mock
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    PkiPropertyCommand command;

    Map<String, Object> properties = new HashMap<String, Object>();

    CertificateRequest certRequest;
    String content = "";
    X509Certificate x509Certificate;
    private static Certificate certificate = new Certificate();

    KeyStoreInfo keyStoreInfo = null;

    byte[] fileBytes = null;

    @Before
    public void setUp() throws Exception {
        properties.put("command", "ENTITYCERTMANAGEMENTREISSUE");

        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.ENTITYCERTMANAGEMENTREISSUE);
        command.setProperties(properties);

        Mockito.doNothing().when(exportedItemsHolder).save(Matchers.anyString(), Matchers.anyObject());

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
        Mockito.when(eServiceRefProxy.getEntityCertificateManagementService()).thenReturn(entityCertificateManagementService);
    }

    @Ignore
    @Test
    public void testRekeyHandler_JKS() throws Exception {
        properties.put(ENTITYNAME, ENTITY);
        properties.put(PASSWORD, PASSWORD_VALUE);
        properties.put(FORMAT, JKS);
        fileBytes = filetoBytes(JKSFILEPATH);

        keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAlias("");
        keyStoreInfo.setPassword(PASSWORD_VALUE.toCharArray());
        keyStoreInfo.setKeyStoreFileData(fileBytes);

        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete(Mockito.anyString())).thenReturn(fileBytes);
        Mockito.when(entityCertificateManagementService.reKeyCertificate(ENTITY, PASSWORD_VALUE.toCharArray(), KeyStoreType.JKS)).thenReturn(keyStoreInfo);

        final PkiCommandResponse pkiCommandResponse = certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY);
        assertEquals(PKICommandResponseType.DOWNLOAD_REQ, pkiCommandResponse.getResponseType());
    }

    @Ignore
    @Test
    public void testRekeyHandler_P12() throws Exception {
        properties.put(ENTITYNAME, ENTITY);
        properties.put(PASSWORD, PASSWORD_VALUE);
        properties.put(FORMAT, P12);
        fileBytes = filetoBytes(P12FILEPATH);

        keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAlias("");
        keyStoreInfo.setPassword(PASSWORD_VALUE.toCharArray());
        keyStoreInfo.setKeyStoreFileData(fileBytes);

        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete(Mockito.anyString())).thenReturn(fileBytes);
        Mockito.when(entityCertificateManagementService.reKeyCertificate(ENTITY, PASSWORD_VALUE.toCharArray(), KeyStoreType.PKCS12)).thenReturn(keyStoreInfo);
        final PkiCommandResponse pkiCommandResponse = certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY);
        assertEquals(PKICommandResponseType.DOWNLOAD_REQ, pkiCommandResponse.getResponseType());
    }

    @Test
    public void testRekeyHandlerNullPassword() throws Exception {
        properties.put(ENTITYNAME, ENTITY);
        properties.put(PASSWORD, null);
        properties.put(FORMAT, P12);
        certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY);
        Mockito.verify(cliUtil).prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), "Password cannot be empty", null);
    }

    @Test
    public void PASSWORD() throws Exception {
        properties.put(ENTITYNAME, ENTITY);
        properties.put(PASSWORD, PASSWORD_VALUE);
        properties.put(FORMAT, null);
        certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY);
        Mockito.verify(cliUtil).prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), "Invalid format or null", null);
    }

    @Test
    public void testRekeyHandler_JKS_SecurityViolationException() throws Exception {
        properties.put(ENTITYNAME, ENTITY);
        properties.put(PASSWORD, PASSWORD_VALUE);
        properties.put(FORMAT, JKS);
        fileBytes = filetoBytes(JKSFILEPATH);

        keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAlias("");
        keyStoreInfo.setPassword(PASSWORD_VALUE.toCharArray());
        keyStoreInfo.setKeyStoreFileData(fileBytes);

        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete(Mockito.anyString())).thenReturn(fileBytes);
        Mockito.when(entityCertificateManagementService.reKeyCertificate(ENTITY, PASSWORD_VALUE.toCharArray(), KeyStoreType.JKS))
                .thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        certMgmtUpdateEntityCommonHandler.process(command);
    }

    @Test
    public void testRekeyHandler_P12_SecurityViolationException() throws Exception {
        properties.put(ENTITYNAME, ENTITY);
        properties.put(PASSWORD, PASSWORD_VALUE);
        properties.put(FORMAT, P12);
        fileBytes = filetoBytes(P12FILEPATH);

        keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAlias("");
        keyStoreInfo.setPassword(PASSWORD_VALUE.toCharArray());
        keyStoreInfo.setKeyStoreFileData(fileBytes);

        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete(Mockito.anyString())).thenReturn(fileBytes);
        Mockito.when(entityCertificateManagementService.reKeyCertificate(ENTITY, PASSWORD_VALUE.toCharArray(), KeyStoreType.PKCS12))
                .thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        certMgmtUpdateEntityCommonHandler.process(command);
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
