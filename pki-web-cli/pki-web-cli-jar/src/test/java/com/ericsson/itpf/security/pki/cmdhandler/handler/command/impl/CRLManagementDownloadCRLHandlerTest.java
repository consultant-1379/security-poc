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

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.cert.X509CRL;
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
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.*;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

/**
 * Test Class for checking Unit test for crlMangementDownloadCRLHandler Class
 *
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLManagementDownloadCRLHandlerTest {

    @InjectMocks
    CRLMangementDownloadCRLHandler crlMangementDownloadCRLHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CRLManagementService crlManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    ExportedItemsHolder exportedItemsHolder;

    @Mock
    CliUtil cliUtil;

    @Mock
    CRLUtils cRLUtils;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CRLMangementDownloadCRLHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    X509CRL x509CRL;

    PkiPropertyCommand pkiPropertyCommand;

    PkiCommandResponse pkiCommandResponse;

    CRL cRL = new CRL();

    CRLInfo cRLInfo = new CRLInfo();

    Map<String, Object> properties = new HashMap<String, Object>();

    List<CRLInfo> cRLInfoList = new ArrayList<CRLInfo>();

    File file = new File("");

    File[] files = { file };

    byte[] byteArray = new byte[(int) file.length()];

    private static java.security.cert.X509Certificate x509Certificate;

    private static Certificate certificate = new Certificate();

    private final static String CA_ENTITY_NAME = "CAENM";
    private final static String SERIAL_NUMBER = "123w4sw523";

    private static Map<CACertificateIdentifier, List<CRLInfo>> crlInfo;

    @Before
    public void setUp() throws Exception {

        properties.put("command", "CRLMANAGEMENTGENERATE");
        pkiPropertyCommand = new PkiPropertyCommand();
        pkiPropertyCommand.setCommandType(PkiCommandType.CRLMANAGEMENTDOWNLOAD);
        pkiPropertyCommand.setProperties(properties);
        pkiCommandResponse = new PkiDownloadRequestToScriptEngine();
        final URL url = Thread.currentThread().getContextClassLoader().getResource("testCA.crl");
        String filename = url.getFile();
        filename = URLDecoder.decode(filename);
        x509CRL = BaseTest.getCRL(filename);
        final X509CRLHolder x509CRLHolder = new X509CRLHolder(x509CRL);
        cRL.setX509CRLHolder(x509CRLHolder);
        cRLInfo.setCrl(cRL);
        cRLInfoList.add(cRLInfo);
        Mockito.doNothing().when(exportedItemsHolder).save(Mockito.anyString(), Mockito.anyObject());

        final URL certificateurl = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");
        final String certificateFilename = certificateurl.getFile();
        x509Certificate = BaseTest.getCertificate(certificateFilename);
        certificate.setX509Certificate(x509Certificate);

        crlInfo = new HashMap<CACertificateIdentifier, List<CRLInfo>>();
        crlInfo = getCRlInfoMap(new CACertificateIdentifier(CA_ENTITY_NAME, SERIAL_NUMBER), 2, crlInfo);
        Mockito.when(eServiceRefProxy.getCrlManagementService()).thenReturn(crlManagementService);
    }

    @Test
    public void testProcessCommand() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "serialno", "lgyus"));

        Mockito.when(crlManagementService.getCRLByCACertificate((CACertificateIdentifier) Mockito.anyObject())).thenReturn(cRLInfo);
        Mockito.when(cliUtil.buildPkiCommandResponse(Mockito.anyString(), Mockito.anyString(), Matchers.<byte[]> any())).thenReturn(pkiCommandResponse);

        pkiCommandResponse = crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertEquals(pkiCommandResponse.getResponseType().toString(), "DOWNLOAD_REQ");
    }

    @Test
    public void testProcessCommand_CRLNumber() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "crlnumber", "1"));

        Mockito.when(crlManagementService.getCRL(Mockito.anyString(), (CRLNumber) Mockito.anyObject())).thenReturn(cRLInfo);

        Mockito.when(cliUtil.buildPkiCommandResponse(Mockito.anyString(), Mockito.anyString(), Matchers.<byte[]> any())).thenReturn(pkiCommandResponse);

        pkiCommandResponse = crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertEquals(pkiCommandResponse.getResponseType().toString(), "DOWNLOAD_REQ");
    }



    @Test
    public void testProcessCommand_NumberFormatException() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "crlnumber", "a"));

        Mockito.when(crlManagementService.getCRL(Mockito.anyString(), (CRLNumber) Mockito.anyObject())).thenReturn(cRLInfo);

        Mockito.when(cliUtil.buildPkiCommandResponse(Mockito.anyString(), Mockito.anyString(), Matchers.<byte[]> any())).thenReturn(pkiCommandResponse);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11102 Unsupported PKI command argument"));

    }

    @Test
    public void testProcessCommand_CAName() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "status", Constants.CERTIFICATE_ACTIVE_STATUS));

        Mockito.when(crlManagementService.getCRL("CAENM", CertificateStatus.ACTIVE, false)).thenReturn(crlInfo);
        Mockito.when(cRLUtils.createCRLFiles(cRLInfoList, "CAENM")).thenReturn(files);
        Mockito.when(cRLUtils.createZipFile((File[]) Mockito.anyObject(), Mockito.anyString())).thenReturn(file);
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(cRLUtils.convertFiletoByteArray((File) Mockito.anyObject())).thenReturn(byteArray);
        Mockito.when(cliUtil.buildPkiCommandResponse(Mockito.anyString(), Mockito.anyString(), Matchers.<byte[]> any())).thenReturn(pkiCommandResponse);
        pkiCommandResponse = crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertEquals(pkiCommandResponse.getResponseType().toString(), "DOWNLOAD_REQ");
    }

    @Test
    public void testProcessCommand_WithoutCaName() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", null, "serialno", "lgyus"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage().contains("11000 Entity Name cannot be null or empty"));
    }

    @Test
    public void testProcessCommand_WithOutSerialNumber() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "serialno", null));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11000 Certificate Serial Number cannot be null or empty."));
    }

    @Test
    public void testProcessCertificateNotFoundException() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "serialno", "lgyus"));

        Mockito.when(crlMangementDownloadCRLHandler.process(pkiPropertyCommand)).thenThrow(new CertificateNotFoundException("Download Failed"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage()
                .contains("Error: 11308 CRL download failed. Certificate not found with the given Serial Number. Please check the logs for more information."));
    }

    @Test
    public void testProcessExpiredCertificateException() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "serialno", "lgyus"));

        Mockito.when(crlMangementDownloadCRLHandler.process(pkiPropertyCommand)).thenThrow(new ExpiredCertificateException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage().contains("Use valid Certificate for operation"));
    }

    @Test
    public void testProcessRevokedCertificateException() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "serialno", "lgyus"));

        Mockito.when(crlMangementDownloadCRLHandler.process(pkiPropertyCommand)).thenThrow(new RevokedCertificateException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage().contains("Certificate already revoked."));
    }

    @Test
    public void testProcessCRLNotFoundException() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "serialno", "lgyus"));

        Mockito.when(crlMangementDownloadCRLHandler.process(pkiPropertyCommand)).thenThrow(new CRLNotFoundException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage().contains("No existing CRL found for CA entity"));
    }

    @Test
    public void testProcessCRLServiceException() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "serialno", "lgyus"));

        Mockito.when(crlMangementDownloadCRLHandler.process(pkiPropertyCommand)).thenThrow(new CRLServiceException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));
    }

    @Test
    public void testProcessIllegalArgumentException() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "status", "lgyus"));

        Mockito.when(commandHandlerUtils.getCertificateStatus("lgyus")).thenThrow(new IllegalArgumentException("Failed Generation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage().contains("The CRL can not be downloaded for the CA Certificate Status lgyus"));
    }

    @Test
    public void testProcessCommand_StatusNull() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "status", null));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage().contains("Certificate Status cannot be null or empty."));
    }

    @Test
    public void testProcessCommand_CRLNumberNull() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "crlnumber", null));


        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage().contains("CRL Number can not be null or empty"));
    }

    @Test
    public void testProcessCANotFoundException() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "serialno", "lgyus"));

        Mockito.when(crlMangementDownloadCRLHandler.process(pkiPropertyCommand)).thenThrow(new CANotFoundException("Download failed"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage().contains("CRL download failed The CA entity with name  CAENM is not found."));
    }

    @Test
    public void testProcessCommand_CRLGenerationException() throws IOException {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "serialno", "lgyus"));

        Mockito.when(cRLUtils.createZipFile((File[]) Mockito.anyObject(), Mockito.anyString())).thenReturn(null);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

        assertTrue(pkiCommandResponse.getMessage().contains("Exception occured during CRL generation"));
    }

    @Test
    public void testProcessCommand_SecurityViolationException() {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "serialno", "lgyus"));

        Mockito.when(crlManagementService.getCRLByCACertificate((CACertificateIdentifier) Mockito.anyObject())).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

    }

    @Test
    public void testProcessCommand_CRLNumber_SecurityViolationException() {

        pkiPropertyCommand.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "crlnumber", "1"));

        Mockito.when(crlManagementService.getCRL(Mockito.anyString(), (CRLNumber) Mockito.anyObject())).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        crlMangementDownloadCRLHandler.process(pkiPropertyCommand);

    }

    private Map<CACertificateIdentifier, List<CRLInfo>> getCRlInfoMap(final CACertificateIdentifier caCertificateIdentifier, final int i, Map<CACertificateIdentifier, List<CRLInfo>> cRLInfo) {
        if (cRLInfo == null) {
            cRLInfo = new HashMap<CACertificateIdentifier, List<CRLInfo>>();
        }
        final List<CRLInfo> crlInfoList = getCRLInfoList(i);
        cRLInfo.put(caCertificateIdentifier, crlInfoList);
        return cRLInfo;
    }

    private List<CRLInfo> getCRLInfoList(final int noOfCRLInfo) {
        final List<CRLInfo> crlInfos = new ArrayList<CRLInfo>();
        for (int i = 0; i < noOfCRLInfo; i++) {
            crlInfos.add(getCRLInfo());
        }
        return crlInfos;
    }

    private CRLInfo getCRLInfo() {
        final CRLInfo crl = new CRLInfo();
        final CRLNumber cRLNumber = new CRLNumber();
        cRLNumber.setSerialNumber(1000);
        crl.setCrlNumber(cRLNumber);
        crl.setIssuerCertificate(certificate);
        crl.setId(12345);
        crl.setNextUpdate(new Date());
        crl.setStatus(CRLStatus.LATEST);
        crl.setThisUpdate(new Date());
        return crl;
    }

    private Map<String, Object> buildProperty(final Object... obj) {
        final Map<String, Object> map = new HashMap<String, Object>();
        for (int i = 0; i < obj.length; i = i + 2) {
            map.put((String) obj[i], obj[i + 1]);
        }
        return map;
    }

}
