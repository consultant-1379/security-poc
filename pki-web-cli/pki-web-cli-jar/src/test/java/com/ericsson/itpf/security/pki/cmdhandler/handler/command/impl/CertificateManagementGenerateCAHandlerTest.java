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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.util.CertificateUtils;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementGenerateCAHandlerTest {

    @InjectMocks
    CertificateManagementGenerateCAHandler certificateManagementGenerateCaHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CACertificateManagementService caCertificateManagementService;

    @Mock
    CertificateUtils certUtil;

    @Mock
    FileUtility fileUtil;

    @Mock
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliUtil;

    @Mock
    ExportedItemsHolder exportedItemsHolder;

    @Mock
    SystemRecorder systemRecorder;

    byte[] fileBytes = null;

    PkiCommandResponse pkiCommandResponse;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementGenerateCAHandler.class);

    PkiPropertyCommand command;

    Map<String, Object> properties = new HashMap<String, Object>();

    Certificate certificate = new Certificate();
    X509Certificate x509Certificate;
    String content = "jkhkl";
    List<Certificate> certificates = new ArrayList<Certificate>();

    CertificateChain certificateChain;
    List<CertificateChain> certificateChainList;

    /**
     * @throws java.lang.Exception
     */

    @Before
    public void setUp() throws Exception {

        properties.put("command", "CACERTIFICATEMANAGEMENTGENERATE");

        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CACERTIFICATEMANAGEMENTGENERATE);
        command.setProperties(properties);

        final URL url = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");
        String filename = url.getFile();
        filename = URLDecoder.decode(filename);
        x509Certificate = BaseTest.getCertificate(filename);

        certificate.setX509Certificate(x509Certificate);
        certificates.add(certificate);

        certificateChain = new CertificateChain();
        certificateChain.setCertificateChain(certificates);

        certificateChainList = new ArrayList<CertificateChain>();

        certificateChainList.add(certificateChain);

        Mockito.doNothing().when(exportedItemsHolder).save(Mockito.anyString(), Mockito.anyObject());
        Mockito.when(eServiceRefProxy.getCaCertificateManagementService()).thenReturn(caCertificateManagementService);
        pkiCommandResponse = new PkiCommandResponse() {

            private static final long serialVersionUID = 2343812310237087351L;

            @Override
            public PKICommandResponseType getResponseType() {
                return PKICommandResponseType.DOWNLOAD_REQ;
            }
        };

    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.CertificateManagementGenerateCAHandler#Process(com.ericsson.itpf.security.pki.cmdhandler.api.command)} .
     *
     * @throws EntityNotFoundException
     * @throws CertificateGenerationException
     */

    @Test
    public void testProcess() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {

        properties.put("entityname", "RBS1234");
        properties.put("format", "JKS");
        properties.put("password", "secure");
        command.setProperties(properties);

        fileBytes = filetoBytes("src/test/resources/RBS1234.jks");
        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete("src/test/resources/RBS1234.jks")).thenReturn(fileBytes);
        Mockito.when(caCertificateManagementService.getCertificateChain("ENMROOTCA")).thenReturn(certificates);
        Mockito.when(caCertificateManagementService.generateCertificate(Mockito.anyString())).thenReturn(certificate);
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");
        Mockito.when(cliUtil.buildPkiCommandResponse(Mockito.anyString(), Mockito.anyString(), Mockito.any(byte[].class))).thenReturn(pkiCommandResponse);
        final PkiCommandResponse pkiCommandResponse = certificateManagementGenerateCaHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);

    }

    @Test
    public void testProcessEntityNameNull() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {

        properties.put("entityname", null);
        properties.put("format", "JKS");
        properties.put("password", "secure");
        command.setProperties(properties);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("11000 Entity Name cannot be null or empty"));

    }

    @Test
    public void testProcessNoChain() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {

        properties.put("entityname", "RBS1234");
        properties.put("nochain", "noChain");
        properties.put("format", "JKS");
        properties.put("password", "secure");
        command.setProperties(properties);
        fileBytes = filetoBytes("src/test/resources/RBS1234.jks");
        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete("src/test/resources/RBS1234.jks")).thenReturn(fileBytes);
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");
        Mockito.when(caCertificateManagementService.generateCertificate(Mockito.anyString())).thenReturn(certificate);
        Mockito.when(cliUtil.buildPkiCommandResponse(Mockito.anyString(), Mockito.anyString(), Mockito.any(byte[].class))).thenReturn(pkiCommandResponse);
        final PkiCommandResponse pkiCommandResponse = certificateManagementGenerateCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);

    }

    @Test
    public void testProcessNoPopUp() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        properties.put("entityname", "ENMROOTCA");
        properties.put("nopopup", "NOPOPUP");
        command.setProperties(properties);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateCaHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Certificate Generated Successfully for ENMROOTCA");

    }

    @Test
    public void testProcessAlgorithmNotFoundException() throws IOException {
        properties.put("entityname", "ENMROOTCA");
        properties.put("nochain", "noChain");
        properties.put("format", "JKS");
        properties.put("password", "secure");
        command.setProperties(properties);

        Mockito.when(certificateManagementGenerateCaHandler.process(command)).thenThrow(new AlgorithmNotFoundException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Provided Algorithm not found, Please check online help for the list of supported algorithms."));
    }

    @Test
    public void testProcessCANotFoundException() throws IOException {
        properties.put("entityname", "ENMROOTCA");
        properties.put("nochain", "noChain");
        properties.put("format", "JKS");
        properties.put("password", "secure");
        command.setProperties(properties);

        Mockito.when(certificateManagementGenerateCaHandler.process(command)).thenThrow(new CANotFoundException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11221 CA not found, Try with existing CA"));
    }

    @Test
    public void testProcessCertificateGenerationException() throws IOException {
        properties.put("entityname", "ENMROOTCA");
        properties.put("nochain", "noChain");
        properties.put("format", "JKS");
        properties.put("password", "secure");
        command.setProperties(properties);

        Mockito.when(certificateManagementGenerateCaHandler.process(command)).thenThrow(new CertificateGenerationException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11305 Exception during Certificate generation null"));
    }

    @Test
    public void testProcessCertificateServiceException() throws IOException {
        properties.put("entityname", "ENMROOTCA");
        properties.put("nochain", "noChain");
        properties.put("format", "JKS");
        properties.put("password", "secure");
        command.setProperties(properties);

        Mockito.when(certificateManagementGenerateCaHandler.process(command)).thenThrow(new CertificateServiceException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));
    }

    @Test
    public void testProcessInvalidCAException() throws IOException {
        properties.put("entityname", "ENMROOTCA");
        properties.put("nochain", "noChain");
        properties.put("format", "JKS");
        properties.put("password", "secure");
        command.setProperties(properties);

        Mockito.when(certificateManagementGenerateCaHandler.process(command)).thenThrow(new InvalidCAException("Invalid CA name"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Invalid CA name"));
    }

    @Test
    public void testProcessExpiredCertificateException() throws IOException {
        properties.put("entityname", "ENMROOTCA");
        properties.put("nochain", "noChain");
        properties.put("format", "JKS");
        properties.put("password", "secure");
        command.setProperties(properties);

        Mockito.when(certificateManagementGenerateCaHandler.process(command)).thenThrow(new ExpiredCertificateException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11603"));
    }

    @Test
    public void testProcessRevokedCertificateException() throws IOException {
        properties.put("entityname", "ENMROOTCA");
        properties.put("nochain", "noChain");
        properties.put("format", "JKS");
        properties.put("password", "secure");
        command.setProperties(properties);

        Mockito.when(certificateManagementGenerateCaHandler.process(command)).thenThrow(new RevokedCertificateException());

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateCaHandler.process(command);
          assertTrue(pkiCommandResponse.getMessage().contains("Error: 11605"));
    }

    @Test
    public void testProcessIOException() throws IOException {
        properties.put("entityname", "ENMROOTCA");
        properties.put("nochain", "noChain");
        properties.put("format", "JKS");
        properties.put("password", "secure");
        command.setProperties(properties);

        Mockito.when(certificateManagementGenerateCaHandler.process(command)).thenThrow(IOException.class);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementGenerateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11002 Exception while storing the certificate null"));
    }

    @Test
    public void testProcess_SecurityViolationException() throws SecurityViolationException, IOException {

        properties.put("entityname", "RBS1234");
        properties.put("format", "JKS");
        properties.put("password", "secure");
        command.setProperties(properties);

        fileBytes = filetoBytes("src/test/resources/RBS1234.jks");
        Mockito.when(pkiWebCliResourceLocalService.getBytesAndDelete("src/test/resources/RBS1234.jks")).thenReturn(fileBytes);
        Mockito.when(caCertificateManagementService.getCertificateChain("ENMROOTCA")).thenReturn(certificates);
        Mockito.when(caCertificateManagementService.generateCertificate(Mockito.anyString())).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("RBS1234.jks");
        Mockito.when(cliUtil.buildPkiCommandResponse(Mockito.anyString(), Mockito.anyString(), Mockito.any(byte[].class))).thenReturn(pkiCommandResponse);
        certificateManagementGenerateCaHandler.process(command);

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
