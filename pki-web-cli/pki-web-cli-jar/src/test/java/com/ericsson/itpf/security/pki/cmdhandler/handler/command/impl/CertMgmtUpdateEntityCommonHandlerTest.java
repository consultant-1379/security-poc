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

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;

@RunWith(MockitoJUnitRunner.class)
public class CertMgmtUpdateEntityCommonHandlerTest {
    private static String ENTITY_NAME = "entity_123";

    @InjectMocks
    CertMgmtUpdateEntityCommonHandler certMgmtUpdateEntityCommonHandler;

    @Mock
    Logger logger;

    @Mock
    CliUtil cliUtil;

    @Mock
    CertMgmtRenewAndModifyEntityHandler certMgmtRenewAndModifyEntityHandler;

    @Mock
    CertMgmtRekeyEntityHandler certMgmtRekeyEntityHandler;

    @Mock
    SystemRecorder systemRecorder;

    @Test
    public void test_process_REKEY_OPTION() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException, EntityNotFoundException,
            InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InterruptedException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenReturn(null);
        certMgmtUpdateEntityCommonHandler.process(command);

        Mockito.verify(certMgmtRekeyEntityHandler).rekeyHandler(command, ENTITY_NAME);
    }

    @Test
    public void test_process_NO_REKEY_OPTION() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException, EntityNotFoundException,
            InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, "some_REISSUE_TYPE");
        command.setProperties(properties);

        Mockito.when(certMgmtRenewAndModifyEntityHandler.renewAndModifyHandler(command, ENTITY_NAME)).thenReturn(null);
        certMgmtUpdateEntityCommonHandler.process(command);

        Mockito.verify(certMgmtRenewAndModifyEntityHandler).renewAndModifyHandler(command, ENTITY_NAME);
    }

    @Test
    public void test_process_NULL_entityName() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException, EntityNotFoundException,
            InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, null);
        command.setProperties(properties);

        certMgmtUpdateEntityCommonHandler.process(command);

        Mockito.verify(cliUtil).prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY, null);
    }

    @Test
    public void test_process_NULL_renewType() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException, EntityNotFoundException,
            InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, null);
        command.setProperties(properties);

        certMgmtUpdateEntityCommonHandler.process(command);

        Mockito.verify(cliUtil).prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.UNSUPPORTED_REISSUE_TYPE, null);
    }

    @Test
    public void test_process_REKEY_OPTION_For_AlgorithmNotFoundException() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException,
            EntityNotFoundException, InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InterruptedException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new AlgorithmNotFoundException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION)));

    }

    @Test
    public void test_process_REKEY_OPTION_For_CertificateGenerationException() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException,
            EntityNotFoundException, InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InterruptedException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new CertificateGenerationException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.EXCEPTION_IN_CERTIFICATE_GENERATION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION)));

    }

    @Test
    public void test_process_REKEY_OPTION_For_CertificateServiceException() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException,
            EntityNotFoundException, InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InterruptedException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new CertificateServiceException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));

    }

    @Test
    public void test_process_REKEY_OPTION_For_InvalidCAException() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException,
            EntityNotFoundException, InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InterruptedException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new InvalidCAException("Invalid CA name"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Invalid CA name"));
    }

    @Test
    public void test_process_REKEY_OPTION_For_EntityNotFoundException() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException,
            EntityNotFoundException, InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InterruptedException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new EntityNotFoundException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ENTITY_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ENTITY_NOT_FOUND)));

    }

    @Test
    public void test_process_REKEY_OPTION_For_IOException() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException,
            EntityNotFoundException, InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InterruptedException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new IOException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_STORING_CERTIFICATE)));

    }

    @Test
    public void test_process_NO_REKEY_OPTION_For_CertificateEncodingException() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException,
            EntityNotFoundException, InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, "some_REISSUE_TYPE");
        command.setProperties(properties);

        Mockito.when(certMgmtRenewAndModifyEntityHandler.renewAndModifyHandler(command, ENTITY_NAME)).thenThrow(new CertificateEncodingException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.EXCEPTION_IN_CERTIFICATE_GENERATION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION)));

    }

    @Test
    public void test_process_REKEY_OPTION_For_InvalidCertificateRequestException() throws Exception {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new InvalidCertificateRequestException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INVALID_CERTIFICATE_REQUEST_EXCEPTION.toInt(), PkiErrorCodes.INVALID_CERTIFICATE_REQUEST)));
    }

    @Test
    public void test_process_REKEY_OPTION_For_InvalidEntityAttributeException() throws Exception {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new InvalidEntityAttributeException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INVALID_ENTITY_ATTRIBUTE_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY)));
    }

    @Test
    public void test_process_REKEY_OPTION_For_ExpiredCertificateException() throws Exception {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new ExpiredCertificateException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_EXPIRED.toInt(), PkiErrorCodes.CERTIFICATE_EXPIRED_EXCEPTION)));
    }

    @Test
    public void test_process_REKEY_OPTION_For_NoSuchAlgorithmException() throws Exception {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new NoSuchAlgorithmException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ALGO_NOT_FOUND.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION)));
    }

    @Test
    public void test_process_REKEY_OPTION_For_RevokedCertificateException() throws Exception {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new RevokedCertificateException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ISSUER_CERTIFICATE_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.CERTIFICATE_ALREADY_REVOKED_EXCEPTION)));
    }

    @Test
    public void test_process_REKEY_OPTION_For_InvalidEntityException() throws Exception {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new InvalidEntityException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INVALID_ENTITY_EXCEPTION.toInt(), PkiErrorCodes.INVALID_ENTITY)));
    }

    @Test
    public void test_process_REKEY_OPTION_For_KeyStoreException() throws Exception {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new KeyStoreException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.INTERNAL_SERVICE_EXCEPTION.toInt(), PkiErrorCodes.KEYSTORE_PROCESSING_EXCEPTON)));
    }

    @Test
    public void test_process_REKEY_OPTION_For_KeyPairGenerationException() throws Exception {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new KeyPairGenerationException());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certMgmtUpdateEntityCommonHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.UNEXPECTED_ERROR.toInt(), PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR + Constants.EMPTY_STRING)));
    }

    @Test
    public void test_process_REKEY_OPTION_SecurityViolationException() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException,
            EntityNotFoundException, InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InterruptedException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, Constants.REKEY_OPTION);
        command.setProperties(properties);

        Mockito.when(certMgmtRekeyEntityHandler.rekeyHandler(command, ENTITY_NAME)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        certMgmtUpdateEntityCommonHandler.process(command);

    }

    @Test
    public void test_process_NO_REKEY_OPTION_SecurityViolationException() throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException, InvalidCAException,
            EntityNotFoundException, InvalidEntityException, KeyPairGenerationException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        final PkiPropertyCommand command = new PkiPropertyCommand();
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(Constants.CERT_GENERATE_ENTITY_NAME, ENTITY_NAME);
        properties.put(Constants.REISSUE_TYPE, "some_REISSUE_TYPE");
        command.setProperties(properties);

        Mockito.when(certMgmtRenewAndModifyEntityHandler.renewAndModifyHandler(command, ENTITY_NAME)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        certMgmtUpdateEntityCommonHandler.process(command);

    }
}
