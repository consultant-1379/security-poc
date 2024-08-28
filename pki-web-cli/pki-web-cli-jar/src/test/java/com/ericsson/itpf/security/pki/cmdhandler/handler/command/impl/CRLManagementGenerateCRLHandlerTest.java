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
import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.CertificateManagementLocalService;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.CRLGenerationStatus;

@RunWith(MockitoJUnitRunner.class)
public class CRLManagementGenerateCRLHandlerTest {

    @InjectMocks
    CRLManagementGenerateCRLHandler crlManagementGenerateCrlHandler;

    @Mock
    Logger logger;

    @Mock
    CliUtil cliUtil;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CertificateManagementLocalService certificateManagementService;

    @Mock
    CRLManagementService crlManagementService;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    private PkiPropertyCommand command;
    private final static String CA_NAME = "ENMPKIROOTCA";
    private final static String MULTI_CA_NAME = "[ENMPKIROOTCA, CA1, CA2, CA3]";
    List<String> caEntityName;
    List<String> multipleCANameList;
    Map<CACertificateIdentifier, CRLGenerationStatus> crlSuccessGenerationMessage;
    Map<CACertificateIdentifier, CRLGenerationStatus> crlFailureGenerationMessage;
    Map<String, Object> properties = new HashMap<String, Object>();
    List<String> statusList;
    private final static String MULTIPLE_STATUS = "active,inactive";
    List<Certificate> certList = new ArrayList<Certificate>();
    Map<CACertificateIdentifier, CRLGenerationStatus> crlGenerationMessageForMultipleCa = new HashMap<CACertificateIdentifier, CRLGenerationStatus>();

    @Before
    public void setUp() {
        command = new PkiPropertyCommand();

        caEntityName = Arrays.asList(CA_NAME.split(","));
        crlSuccessGenerationMessage = getCRLGenerationMessageForCaEntity(CRLGenerationStatus.CRL_GENERATION_SUCCESSFUL);
        crlFailureGenerationMessage = getCRLGenerationMessageForCaEntity(CRLGenerationStatus.CA_ENTITY_NOT_FOUND);
        Certificate caCert1 = new Certificate();
        Certificate caCert2 = new Certificate();
        caCert1.setStatus(CertificateStatus.ACTIVE);
        caCert2.setStatus(CertificateStatus.INACTIVE);
        certList.add(caCert1);
        certList.add(caCert2);
        statusList = Arrays.asList(MULTIPLE_STATUS.split(","));

        multipleCANameList = Arrays.asList(MULTI_CA_NAME.replaceAll("\\[|\\]", "").split(","));

        crlGenerationMessageForMultipleCa = getCRLGenerationMessageForMultipleCaEntities(crlGenerationMessageForMultipleCa, multipleCANameList);
        Mockito.when(eServiceRefProxy.getCrlManagementService()).thenReturn(crlManagementService);
    }

    @Test
    public void testProcess() {
        properties = buildProperty("caentityname", CA_NAME, "serialno", "1234");
        command.setProperties(properties);
        final PkiMessageCommandResponse message = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        Assert.assertEquals(message.getMessage(), "CRL generated successfully by " + CA_NAME + ".");
    }

    @Test
    public void testProcess_WithCaName() {
        properties = buildProperty("caentityname", CA_NAME);
        command.setProperties(properties);
        Mockito.when(cliUtil.splitBySeprator(CA_NAME, ", ")).thenReturn(caEntityName);
        Mockito.when(certificateManagementService.listCertificates(CA_NAME, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(certList);
        Mockito.when(crlManagementService.generateCRL(caEntityName, CertificateStatus.ACTIVE)).thenReturn(crlSuccessGenerationMessage);
        Mockito.when(crlManagementService.generateCRL(caEntityName, CertificateStatus.INACTIVE)).thenReturn(crlSuccessGenerationMessage);
        Mockito.when(cliUtil.removeUnwantedCommaFromString((StringBuilder) Mockito.any())).thenReturn("12345");
        final PkiNameMultipleValueCommandResponse message = (PkiNameMultipleValueCommandResponse) crlManagementGenerateCrlHandler.process(command);
        Assert.assertTrue(message.getAdditionalInformation().contains("CRL generated successfully"));
    }

    @Test
    public void testProcess_WithEmptyCaName() {
        properties = buildProperty("caentityname", "");
        command.setProperties(properties);
        final PkiMessageCommandResponse message = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        Assert.assertTrue(message.getMessage().contains("Error: 11000 Entity Name cannot be null or empty."));
    }

    @Test
    public void testProcess_WithEmptySerialNumber() {
        properties = buildProperty("caentityname", CA_NAME, "serialno", null);
        command.setProperties(properties);
        final PkiMessageCommandResponse message = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        Assert.assertEquals(message.getMessage(), "Error: 11000 Certificate Serial Number cannot be null or empty.");
    }

    @Test
    public void testProcess_WithActiveStatus() {
        properties = buildProperty("caentityname", CA_NAME, "status", Constants.CERTIFICATE_ACTIVE_STATUS);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(cliUtil.splitBySeprator(CA_NAME, ", ")).thenReturn(caEntityName);
        Mockito.when(crlManagementService.generateCRL(caEntityName, CertificateStatus.ACTIVE)).thenReturn(crlSuccessGenerationMessage);
        Mockito.when(cliUtil.removeUnwantedCommaFromString((StringBuilder) Mockito.any())).thenReturn("12345");
        final PkiNameMultipleValueCommandResponse message = (PkiNameMultipleValueCommandResponse) crlManagementGenerateCrlHandler.process(command);
        Assert.assertTrue(!message.isEmpty());
    }

    @Test
    public void testProcess_WithInActiveStatus() {
        properties = buildProperty("caentityname", CA_NAME, "status", Constants.CERTIFICATE_INACTIVE_STATUS);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCertificateStatus("inactive")).thenReturn(CertificateStatus.INACTIVE);
        Mockito.when(cliUtil.splitBySeprator(CA_NAME, ", ")).thenReturn(caEntityName);
        Mockito.when(crlManagementService.generateCRL(caEntityName, CertificateStatus.INACTIVE)).thenReturn(crlSuccessGenerationMessage);
        Mockito.when(cliUtil.removeUnwantedCommaFromString((StringBuilder) Mockito.any())).thenReturn("12345");
        final PkiNameMultipleValueCommandResponse message = (PkiNameMultipleValueCommandResponse) crlManagementGenerateCrlHandler.process(command);
        Assert.assertTrue(!message.isEmpty());
    }

    @Test
    public void testProcessCommand_IllegalArgumentException() throws IOException {

        properties = buildProperty("caentityname", CA_NAME, "status", "Invalid Status");
        command.setProperties(properties);
        Mockito.doThrow(new IllegalArgumentException("Certificate status not supported. Supported values are [active,revoked,expired] ")).when(commandHandlerUtils)
                .getCertificateStatus("invalid status");
        Mockito.when(cliUtil.splitBySeprator(MULTI_CA_NAME, ",")).thenReturn(caEntityName);
        Mockito.when(crlManagementService.generateCRL(caEntityName, CertificateStatus.INACTIVE)).thenReturn(crlSuccessGenerationMessage);
        final PkiMessageCommandResponse message = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        assertTrue(message
                .getMessage()
                .contains(
                        "Error: 11302 CRL generation failed.The CRL can not be generated for the CA Certificate Status Invalid Status Allowed CA Certificate statues are ACTIVE and INACTIVE. Please check user guide or online help for command syntax"));
    }

    @Test
    public void testProcess_CaEntityNotFound() {
        properties = buildProperty("caentityname", CA_NAME, "status", Constants.CERTIFICATE_ACTIVE_STATUS);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(cliUtil.splitBySeprator(CA_NAME, ", ")).thenReturn(caEntityName);
        Mockito.when(cliUtil.removeUnwantedCommaFromString((StringBuilder) Mockito.any())).thenReturn("ENMPKIROOTCA");
        Mockito.when(crlManagementService.generateCRL(caEntityName, CertificateStatus.ACTIVE)).thenReturn(crlFailureGenerationMessage);
        final PkiNameMultipleValueCommandResponse message = (PkiNameMultipleValueCommandResponse) crlManagementGenerateCrlHandler.process(command);
        Assert.assertTrue(message.getAdditionalInformation().contains("CRL generation failed for ENMPKIROOTCA. Please check the details below."));
    }

    @Test
    public void testProcess_WithMultipleStatus() {
        properties = buildProperty("caentityname", CA_NAME, "status", "[active,inactive]");
        command.setProperties(properties);
        Mockito.when(cliUtil.splitBySeprator(MULTIPLE_STATUS, ", ")).thenReturn(statusList);
        final PkiMessageCommandResponse message = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        Assert.assertTrue(message.getMessage().contains("Multiple CA certificate statuses"));
    }

    @Test
    public void testProcess_WithSerialNUmberEmpty() {
        properties = buildProperty("caentityname", MULTI_CA_NAME, "status", Constants.CERTIFICATE_ACTIVE_STATUS);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(cliUtil.splitBySeprator(MULTI_CA_NAME.replaceAll("\\[|\\]", ""), ", ")).thenReturn(multipleCANameList);
        Mockito.when(cliUtil.removeUnwantedCommaFromString((StringBuilder) Mockito.any())).thenReturn(" CA2,  CA1, ENMPKIROOTCA and  CA3");
        Mockito.when(crlManagementService.generateCRL(multipleCANameList, CertificateStatus.ACTIVE)).thenReturn(crlGenerationMessageForMultipleCa);
        final PkiNameMultipleValueCommandResponse message = (PkiNameMultipleValueCommandResponse) crlManagementGenerateCrlHandler.process(command);
        Assert.assertTrue(message.getAdditionalInformation().contains("CRL generation failed"));
    }

    @Test
    public void testProcessCommand_ExpiredCertificateException() {

        command.setProperties(buildProperty("caentityname", MULTI_CA_NAME, "status", Constants.CERTIFICATE_EXPIRED_STATUS));
        Mockito.when(commandHandlerUtils.getCertificateStatus("expired")).thenReturn(CertificateStatus.EXPIRED);
        Mockito.when(cliUtil.splitBySeprator(MULTI_CA_NAME.replaceAll("\\[|\\]", ""), ", ")).thenReturn(multipleCANameList);
        Mockito.doThrow(new InvalidCertificateStatusException()).when(crlManagementService).generateCRL(multipleCANameList, CertificateStatus.EXPIRED);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        assertEquals(
                pkiCommandResponse.getMessage().trim(),
                "Error: 11609 CRL generation failed.The CRL can not be generated for the CA Certificate Status EXPIRED Allowed CA Certificate statues are ACTIVE and INACTIVE. Please check user guide or online help for command syntax.");
    }

    @Test
    public void testProcessCommand_RevokedCertificateException() {

        command.setProperties(buildProperty("caentityname", MULTI_CA_NAME, "status", Constants.CERTIFICATE_REVOKED_STATUS));
        Mockito.when(commandHandlerUtils.getCertificateStatus("revoked")).thenReturn(CertificateStatus.REVOKED);
        Mockito.when(cliUtil.splitBySeprator(MULTI_CA_NAME.replaceAll("\\[|\\]", ""), ", ")).thenReturn(multipleCANameList);
        Mockito.doThrow(new InvalidCertificateStatusException()).when(crlManagementService).generateCRL(multipleCANameList, CertificateStatus.REVOKED);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        assertEquals(
                pkiCommandResponse.getMessage().trim(),
                "Error: 11609 CRL generation failed.The CRL can not be generated for the CA Certificate Status REVOKED Allowed CA Certificate statues are ACTIVE and INACTIVE. Please check user guide or online help for command syntax.");
    }

    @Test
    public void testProcessCommand_WithoutCaName() throws IOException {
        MockitoAnnotations.initMocks(crlManagementGenerateCrlHandler);
        properties = buildProperty("caentityname", "", "serialno", "lgyus");
        command.setProperties(properties);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("11000 Entity Name cannot be null or empty"));
    }

    @Test
    public void testProcessCommand_WithoutSerialNo() throws IOException {
        MockitoAnnotations.initMocks(crlManagementGenerateCrlHandler);
        properties = buildProperty("caentityname", "Erbs123", "serialno", null);
        command.setProperties(properties);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Certificate Serial Number cannot be null or empty"));
    }

    @Test
    public void testProcessCertificateNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(crlManagementGenerateCrlHandler);
        properties = buildProperty("caentityname", "Erbs1231", "serialno", "lgyus");
        command.setProperties(properties);
        Mockito.doThrow(new CertificateNotFoundException()).when(crlManagementService).generateCRL((CACertificateIdentifier) Mockito.anyObject());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(PkiErrorCodes.INVALID_CA_AND_SERIAL_NUMBER));
    }

    @Test
    public void testProcessExpiredCertificateException() throws IOException {
        MockitoAnnotations.initMocks(crlManagementGenerateCrlHandler);
        properties = buildProperty("caentityname", "Erbs123", "serialno", "lgyus");
        command.setProperties(properties);
        Mockito.when(crlManagementGenerateCrlHandler.process(command)).thenThrow(new ExpiredCertificateException("Use valid Certificate for operation"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Use valid Certificate for operation"));
    }

    @Test
    public void testProcessRevokedCertificateException() throws IOException {
        MockitoAnnotations.initMocks(crlManagementGenerateCrlHandler);
        properties = buildProperty("caentityname", "Erbs123", "serialno", "lgyus");
        command.setProperties(properties);
        Mockito.when(crlManagementGenerateCrlHandler.process(command)).thenThrow(new RevokedCertificateException("Certificate already revoked."));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11604 CRL generation failed.CA Certificate is revoked."));
    }

    @Test
    @Ignore
    public void testProcessCRLServiceException() throws IOException {
        MockitoAnnotations.initMocks(crlManagementGenerateCrlHandler);
        properties = buildProperty("caentityname", "Erbs123", "serialno", "lgyus");
        command.setProperties(properties);
        Mockito.when(crlManagementGenerateCrlHandler.process(command)).thenThrow(new CRLServiceException("Failed Generation"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("An error occurred while executing the PKI command on the system. Consult the error and logs for more information."));

    }

    @Test
    public void testProcessCRLGenerationException() throws IOException {
        MockitoAnnotations.initMocks(crlManagementGenerateCrlHandler);
        properties = buildProperty("caentityname", "Erbs123", "serialno", "lgyus");
        command.setProperties(properties);
        Mockito.when(crlManagementGenerateCrlHandler.process(command)).thenThrow(new CRLGenerationException("CRL Generation Exception"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Exception occured during CRL generation"));
    }

    @Test
    public void testProcessCANotFoundException() throws IOException {
        MockitoAnnotations.initMocks(crlManagementGenerateCrlHandler);
        properties = buildProperty("caentityname", "Erbs123", "serialno", "lgyus");
        command.setProperties(properties);
        Mockito.when(crlManagementGenerateCrlHandler.process(command)).thenThrow(new CANotFoundException("CRL Generation Exception"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) crlManagementGenerateCrlHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("The CA entity with name  Erbs123 is not found"));
    }

    @Test
    public void testProcessCommand_SecurityViolationException() throws SecurityViolationException {
        properties = buildProperty("caentityname", CA_NAME, "status", Constants.CERTIFICATE_ACTIVE_STATUS);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCertificateStatus("active")).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(cliUtil.splitBySeprator(CA_NAME, ", ")).thenReturn(caEntityName);
        Mockito.when(crlManagementService.generateCRL(caEntityName, CertificateStatus.ACTIVE)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        crlManagementGenerateCrlHandler.process(command);
    }

    /**
     * @param crlGenerationMessage
     * @return
     */
    private Map<CACertificateIdentifier, CRLGenerationStatus> getCRLGenerationMessageForMultipleCaEntities(final Map<CACertificateIdentifier, CRLGenerationStatus> crlGenerationMessage,
            final List<String> caNameList) {
        final CACertificateIdentifier caCertificateIdentifier1 = new CACertificateIdentifier(caNameList.get(0), "12345");
        final CACertificateIdentifier caCertificateIdentifier2 = new CACertificateIdentifier(caNameList.get(1), "12346");
        final CACertificateIdentifier caCertificateIdentifier3 = new CACertificateIdentifier(caNameList.get(2), "12347");
        final CACertificateIdentifier caCertificateIdentifier4 = new CACertificateIdentifier(caNameList.get(3), "12348");
        final CACertificateIdentifier caCertificateIdentifier5 = new CACertificateIdentifier(caNameList.get(0), "12341");
        final CACertificateIdentifier caCertificateIdentifier6 = new CACertificateIdentifier(caNameList.get(1), "12342");
        final CACertificateIdentifier caCertificateIdentifier7 = new CACertificateIdentifier(caNameList.get(2), "12343");

        crlGenerationMessage.put(caCertificateIdentifier1, CRLGenerationStatus.CA_ENTITY_NOT_FOUND);
        crlGenerationMessage.put(caCertificateIdentifier2, CRLGenerationStatus.CRL_GENERATION_SUCCESSFUL);
        crlGenerationMessage.put(caCertificateIdentifier3, CRLGenerationStatus.CRL_GENERATION_SUCCESSFUL);
        crlGenerationMessage.put(caCertificateIdentifier4, CRLGenerationStatus.CERTIFICATE_NOT_FOUND);
        crlGenerationMessage.put(caCertificateIdentifier5, CRLGenerationStatus.CRLGENERATION_INFO_NOT_FOUND);
        crlGenerationMessage.put(caCertificateIdentifier6, CRLGenerationStatus.CRLGENERATION_INFO_NOT_VALID);
        crlGenerationMessage.put(caCertificateIdentifier7, CRLGenerationStatus.GENERATE_CRL_ERROR);
        return crlGenerationMessage;
    }

    private Map<CACertificateIdentifier, CRLGenerationStatus> getCRLGenerationMessageForCaEntity(final CRLGenerationStatus status) {
        final Map<CACertificateIdentifier, CRLGenerationStatus> crlGenerationMessage = new HashMap<CACertificateIdentifier, CRLGenerationStatus>();
        final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCerficateSerialNumber("12345");
        caCertificateIdentifier.setCaName(CA_NAME);
        crlGenerationMessage.put(caCertificateIdentifier, status);
        return crlGenerationMessage;
    }

    private Map<String, Object> buildProperty(final Object... obj) {
        final Map<String, Object> map = new HashMap<String, Object>();
        for (int i = 0; i < obj.length; i = i + 2) {
            map.put((String) obj[i], obj[i + 1]);
        }
        return map;
    }

}
