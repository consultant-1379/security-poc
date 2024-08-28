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
package com.ericsson.oss.itpf.security.credmservice.api.exception;

import static org.junit.Assert.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import org.junit.Test;

public class CredentialManagerBasicExceptionsTest {

    private static String TEST_ERROR_MESSAGE = "TestErrorMessage";

    @Test
    public final void testExceptionConstructors() {
        verifyException(CredentialManagerAlgorithmNotSupportedException.class, CredentialManagerErrorCodes.ALGORITHM_NOT_SUPPORTED);
        verifyException(CredentialManagerCANotFoundException.class, CredentialManagerErrorCodes.CA_NOT_FOUND);
        verifyException(CredentialManagerCertificateEncodingException.class, CredentialManagerErrorCodes.CERTIFICATE_ENCODING_ERROR);
        verifyException(CredentialManagerCertificateExsitsException.class, CredentialManagerErrorCodes.CERTIFICATE_EXISTS);
        verifyException(CredentialManagerCertificateGenerationException.class, CredentialManagerErrorCodes.CERITIFICATE_GENERATION_ERROR);
        verifyException(CredentialManagerCertificateNotFoundException.class, CredentialManagerErrorCodes.CERTIFICATE_NOT_FOUND);
        verifyException(CredentialManagerCertificateServiceException.class, CredentialManagerErrorCodes.CERTIFICATE_SERVICE_ERROR);
        verifyException(CredentialManagerCRLEncodingException.class, CredentialManagerErrorCodes.CERTIFICATE_ENCODING_ERROR);
        verifyException(CredentialManagerCRLServiceException.class, CredentialManagerErrorCodes.CRL_SERVICE_ERROR);
        verifyException(CredentialManagerEntityNotFoundException.class, CredentialManagerErrorCodes.ENTITY_NOT_FOUND);
        verifyException(CredentialManagerInternalServiceException.class, CredentialManagerErrorCodes.UNEXPECTED_INTERNAL_ERROR);
        verifyException(CredentialManagerInvalidArgumentException.class, CredentialManagerErrorCodes.INVALID_ARGUMENT);
        verifyException(CredentialManagerInvalidCAException.class, CredentialManagerErrorCodes.INVALID_CA);
        verifyException(CredentialManagerInvalidCSRException.class, CredentialManagerErrorCodes.INVALID_CSR);
        verifyException(CredentialManagerInvalidEntityException.class, CredentialManagerErrorCodes.ENTITY_INVALID);
        verifyException(CredentialManagerInvalidProfileException.class, CredentialManagerErrorCodes.PROFILE_INVALID);
        verifyException(CredentialManagerKeySizeNotSupportedException.class, CredentialManagerErrorCodes.KEY_SIZE_NOT_SUPPORTED);
        verifyException(CredentialManagerOtpExpiredException.class, CredentialManagerErrorCodes.OTP_EXPIRED);
        verifyException(CredentialManagerProfileNotFoundException.class, CredentialManagerErrorCodes.PROFILE_NOT_FOUND);
        verifyException(CredentialManagerSNNotFoundException.class, CredentialManagerErrorCodes.SN_NOT_FOUND);
        verifyException(CredentialManagerExpiredCertificateException.class, CredentialManagerErrorCodes.EXPIRED_CERTIFICATE);
        verifyException(CredentialManagerAlreadyRevokedCertificateException.class, CredentialManagerErrorCodes.REVOKED_CERTIFICATE);
        verifyException(CredentialManagerServiceException.class, CredentialManagerErrorCodes.SUGGESTED_SOLUTION_CONSULT_ERROR_LOGS);
        verifyException(CredentialManagerInvalidOtpException.class, CredentialManagerErrorCodes.OTP_INVALID);
    }

    private void verifyException(final Class<? extends CredentialManagerServiceException> clazz, final String errorCode) {
        verifyMessageAndThrowable(clazz, errorCode);
        verifyMessage(clazz, errorCode);
        verifyThrowable(clazz, errorCode);
        verify(clazz, errorCode);
    }

    private void verifyMessageAndThrowable(final Class<? extends CredentialManagerServiceException> clazz, final String errorCode) {
        Constructor<?> ctor;
        try {
            ctor = clazz.getConstructor(String.class, Throwable.class);
            final CredentialManagerServiceException ex = (CredentialManagerServiceException) ctor.newInstance(TEST_ERROR_MESSAGE, new Throwable());
            assertTrue(ex.getErrorMessage().equals(errorCode + " : " + TEST_ERROR_MESSAGE));
        } catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void verifyMessage(final Class<? extends CredentialManagerServiceException> clazz, final String errorCode) {
        Constructor<?> ctor;
        try {
            ctor = clazz.getConstructor(String.class);
            final CredentialManagerServiceException ex = (CredentialManagerServiceException) ctor.newInstance(TEST_ERROR_MESSAGE);
            assertTrue(ex.getErrorMessage().equals(errorCode + " : " + TEST_ERROR_MESSAGE));
        } catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void verifyThrowable(final Class<? extends CredentialManagerServiceException> clazz, final String errorCode) {
        Constructor<?> ctor;
        try {
            ctor = clazz.getConstructor(Throwable.class);
            final CredentialManagerServiceException ex = (CredentialManagerServiceException) ctor.newInstance(new Throwable());
            assertTrue(ex.getErrorMessage().equals(errorCode));
        } catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void verify(final Class<? extends CredentialManagerServiceException> clazz, final String errorCode) {
        Constructor<?> ctor;
        try {
            ctor = clazz.getConstructor();
            final CredentialManagerServiceException ex = (CredentialManagerServiceException) ctor.newInstance();
            assertTrue(ex.getErrorMessage().equals(errorCode));
        } catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    //Test for parent exception field (CredentialManagerServiceException is abstract, so it cannot be used)
    @Test
    public void suggestionsServiceExceptionTest() {
        Class<CredentialManagerAlgorithmNotSupportedException> cl = CredentialManagerAlgorithmNotSupportedException.class;
        try {
            CredentialManagerAlgorithmNotSupportedException ex1 = cl.getConstructor().newInstance();
            assertTrue(ex1.getSuggestedSolution().equals(CredentialManagerErrorCodes.SUGGESTED_SOLUTION_CONSULT_ERROR_LOGS));
            ex1.setSuggestedSolution("Suggested solution test");
            assertTrue(ex1.getSuggestedSolution().equals("Suggested solution test"));
            ex1.setSuggestedSolution("Suggested solution test 2", "Arg1");
            assertTrue(ex1.getSuggestedSolution().contains("Suggested solution test 2"));
        } catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | SecurityException e) {
            e.printStackTrace();
        }

    }
}
