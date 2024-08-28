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

import java.io.IOException;
import java.net.URL;
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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;

@RunWith(MockitoJUnitRunner.class)
public class CRLManagmentListCRLHandlerTest {

    @InjectMocks
    CRLManagmentListCRLHandler crlManagmentListCrlHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtils;

    @Mock
    CRLManagementService crlManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CRLManagmentListCRLHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    private static PkiPropertyCommand command;

    private static java.security.cert.X509Certificate x509Certificate;

    private static Certificate certificate = new Certificate();

    private static HashMap<CACertificateIdentifier, List<CRLInfo>> cRLInfo;

    private CACertificateIdentifier caCertificateIdentifier;

    private List<CRLInfo> crlInfoList;

    private final static String CA_ENTITY_NAME = "CAENM";
    private final static String SERIAL_NUMBER = "123w4sw523";
    private final static String SERIAL_NUMBER_CAENM = "123w4sw5zasd23";

    @Before
    public void setUp() throws Exception {
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CRLMANAGEMENTLIST);
        MockitoAnnotations.initMocks(crlManagmentListCrlHandler);
        final URL url = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");
        final String filename = url.getFile();
        x509Certificate = BaseTest.getCertificate(filename);
        certificate.setX509Certificate(x509Certificate);

        cRLInfo = new HashMap<CACertificateIdentifier, List<CRLInfo>>();
        cRLInfo = getCRlInfoMap(new CACertificateIdentifier(CA_ENTITY_NAME, SERIAL_NUMBER), 2, cRLInfo);
        cRLInfo = getCRlInfoMap(new CACertificateIdentifier(CA_ENTITY_NAME, SERIAL_NUMBER_CAENM), 2, cRLInfo);

        caCertificateIdentifier = new CACertificateIdentifier("CAENM", SERIAL_NUMBER);

        crlInfoList = getCRLInfoList(4);
        Mockito.when(eServiceRefProxy.getCrlManagementService()).thenReturn(crlManagementService);

    }

    @Test
    public void testProcessCommand() throws IOException {
        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "100", "status", "active"));
        Mockito.when(crlManagementService.getCRL(CA_ENTITY_NAME, CertificateStatus.ACTIVE, false)).thenReturn(cRLInfo);
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.ACTIVE);
        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) crlManagmentListCrlHandler.process(command);
        assertEquals(pkiCommandResponse.getAdditionalInformation(), "List of CRL(s)");
    }

    @Test
    public void testProcessCommand_WithInvalidCount() throws IOException {
        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "abc", "status", "active"));
        Mockito.when(crlManagementService.getCRL(CA_ENTITY_NAME, CertificateStatus.ACTIVE, false)).thenReturn(cRLInfo);
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.ACTIVE);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagmentListCrlHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11102 Unsupported PKI command argument"));
    }

    @Test
    public void testProcessCommand_InactiveStatus() throws IOException {
        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "1", "status", Constants.CERTIFICATE_INACTIVE_STATUS));
        Mockito.when(crlManagementService.getCRL(CA_ENTITY_NAME, CertificateStatus.ACTIVE, false)).thenReturn(getCrlInfos(CA_ENTITY_NAME, SERIAL_NUMBER, SERIAL_NUMBER_CAENM));
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.INACTIVE);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagmentListCrlHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage().trim(), "Error: 11608 CRL is not yet generated for CA Entity");
    }

    @Test
    public void testProcessCommand_IllegalArgumentException() throws IOException {

        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "1", "status", "Invalid Status"));
        Mockito.when(crlManagementService.getCRL(CA_ENTITY_NAME, CertificateStatus.ACTIVE, false)).thenReturn(getCrlInfos(CA_ENTITY_NAME, SERIAL_NUMBER, SERIAL_NUMBER_CAENM));
        Mockito.doThrow(new IllegalArgumentException("Certificate status not supported. Supported values are [active,revoked,expired] ")).when(commandHandlerUtils)
                .getCertificateStatus("invalid status");
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagmentListCrlHandler.process(command);
        assertTrue(pkiCommandResponse
                .getMessage()
                .contains(
                        "Error: 11302 CRL listing failed.The CRL can not be listed for the CA Certificate Status Invalid Status Allowed CA Certificate statues are ACTIVE and INACTIVE. Please check user guide or online help for command syntax"));
    }

    @Test
    public void testProcessCommand_WithoutCaName() {

        command.setProperties(buildProperty("caentityname", null, "count", "1", "status", "active", "serialno", SERIAL_NUMBER));
        Mockito.when(crlManagementService.getCRL(CA_ENTITY_NAME, CertificateStatus.ACTIVE, false)).thenReturn(getCrlInfos(CA_ENTITY_NAME, SERIAL_NUMBER, SERIAL_NUMBER_CAENM));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagmentListCrlHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11000 Entity Name cannot be null or empty.");
    }

    @Test
    public void testProcessCommand_CANotFoundException() {
        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "1", "status", Constants.CERTIFICATE_ACTIVE_STATUS));
        Mockito.doThrow(new CANotFoundException()).when(crlManagementService).getCRL(CA_ENTITY_NAME, CertificateStatus.ACTIVE, false);
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.ACTIVE);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagmentListCrlHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11221 CRL listing failed. The CA entity with name CAENM is not found ");
    }

    @Test
    public void testProcessCommand_CertificateNotFoundException() {

        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "1", "status", Constants.CERTIFICATE_ACTIVE_STATUS));
        Mockito.doThrow(new CertificateNotFoundException()).when(crlManagementService).getCRL(CA_ENTITY_NAME, CertificateStatus.ACTIVE, false);
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.ACTIVE);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagmentListCrlHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(),
                "Error: 11308 CRL listing failed. Certificate not found with the given Certificate Status. Please check the logs for more information.");
    }

    @Test
    public void testProcessCommand_CRLNotFoundException() {

        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "1", "status", Constants.CERTIFICATE_ACTIVE_STATUS));
        Mockito.doThrow(new CRLNotFoundException("")).when(crlManagementService).getCRL(CA_ENTITY_NAME, CertificateStatus.ACTIVE, false);
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.ACTIVE);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagmentListCrlHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage().trim(), "Error: 11608 CRL is not yet generated for CA Entity CAENM");
    }

    @Test
    public void testProcessCommand_CRLServiceException() {

        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "1", "status", Constants.CERTIFICATE_ACTIVE_STATUS));
        Mockito.doThrow(new CRLServiceException("")).when(crlManagementService).getCRL(CA_ENTITY_NAME, CertificateStatus.ACTIVE, false);
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.ACTIVE);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagmentListCrlHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));
    }

    @Test
    public void testProcessCommand_ExpiredCertificateException() {

        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "1", "status", Constants.CERTIFICATE_EXPIRED_STATUS));
        Mockito.doThrow(new InvalidCertificateStatusException()).when(crlManagementService).getCRL(CA_ENTITY_NAME, CertificateStatus.EXPIRED, false);
        Mockito.when(commandHandlerUtils.getCertificateStatus("expired")).thenReturn(CertificateStatus.EXPIRED);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagmentListCrlHandler.process(command);
        assertEquals(
                pkiCommandResponse.getMessage().trim(),
                "Error: 11302 CRL listing failed.The CRL can not be listed for the CA Certificate Status EXPIRED Allowed CA Certificate statues are ACTIVE and INACTIVE. Please check user guide or online help for command syntax.");
    }

    @Test
    public void testProcessCommand_RevokedCertificateException() {

        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "1", "status", Constants.CERTIFICATE_REVOKED_STATUS));
        Mockito.doThrow(new InvalidCertificateStatusException()).when(crlManagementService).getCRL(CA_ENTITY_NAME, CertificateStatus.REVOKED, false);
        Mockito.when(commandHandlerUtils.getCertificateStatus("revoked")).thenReturn(CertificateStatus.REVOKED);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagmentListCrlHandler.process(command);
        assertEquals(
                pkiCommandResponse.getMessage().trim(),
                "Error: 11302 CRL listing failed.The CRL can not be listed for the CA Certificate Status REVOKED Allowed CA Certificate statues are ACTIVE and INACTIVE. Please check user guide or online help for command syntax.");
    }

    @Test
    public void testProcessCommand_CertificateIdentifier() throws IOException {

        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "100", "serialno", SERIAL_NUMBER));
        Mockito.when(crlManagementService.getAllCRLs(caCertificateIdentifier)).thenReturn(crlInfoList);
        final PkiNameMultipleValueCommandResponse pkiCommandResponse = (PkiNameMultipleValueCommandResponse) crlManagmentListCrlHandler.process(command);
        assertEquals(pkiCommandResponse.getAdditionalInformation(), "List of CRL(s)");
    }

    @Test
    public void testProcessCommand_WithoutSerialNumber() throws IOException {

        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "100", "serialno", null));
        Mockito.when(crlManagementService.getAllCRLs(caCertificateIdentifier)).thenReturn(crlInfoList);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagmentListCrlHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Error: 11000 Certificate Serial Number cannot be null or empty.");
    }

    @Test
    public void testProcessCommand_SecurityViolationException() throws IOException {
        command.setProperties(buildProperty("caentityname", CA_ENTITY_NAME, "count", "100", "status", "active"));
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(crlManagementService.getCRL(CA_ENTITY_NAME, CertificateStatus.ACTIVE, false)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        crlManagmentListCrlHandler.process(command);
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

    private List<CRLInfo> getCRLInfoList(final int noOfCRLInfo) {
        final List<CRLInfo> crlInfos = new ArrayList<CRLInfo>();
        for (int i = 0; i < noOfCRLInfo; i++) {
            crlInfos.add(getCRLInfo());
        }
        return crlInfos;
    }

    private HashMap<CACertificateIdentifier, List<CRLInfo>> getCRlInfoMap(final CACertificateIdentifier caCertificateIdentifier, final int i, HashMap<CACertificateIdentifier, List<CRLInfo>> cRLInfo) {
        if (cRLInfo == null) {
            cRLInfo = new HashMap<CACertificateIdentifier, List<CRLInfo>>();
        }
        final List<CRLInfo> crlInfoList = getCRLInfoList(i);
        cRLInfo.put(caCertificateIdentifier, crlInfoList);
        return cRLInfo;
    }

    private HashMap<CACertificateIdentifier, List<CRLInfo>> getCrlInfos(final String caentityname, final String serialNumberInactivecert, final String serialNumberInactiveCertificate) {
        cRLInfo = new HashMap<CACertificateIdentifier, List<CRLInfo>>();
        cRLInfo = getCRlInfoMap(new CACertificateIdentifier(caentityname, serialNumberInactivecert), 2, cRLInfo);
        return cRLInfo = getCRlInfoMap(new CACertificateIdentifier(caentityname, serialNumberInactiveCertificate), 2, cRLInfo);
    }
}