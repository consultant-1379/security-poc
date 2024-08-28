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
package com.ericsson.oss.itpf.security.pki.core.common.utils;

import java.io.*;
import java.security.KeyPair;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;

//TODO to be moved to pki-common repo. User story ref : TORF-57836
public class CommonUtil {

    @Inject
    static Logger logger;

    @Inject
    static SystemRecorder systemRecorder;

    private CommonUtil() {

    }

    /**
     * Converts the KeyPair {@link KeyPair} object to the byte array from.
     * 
     * @param obj
     *            object to be converted to byte array form.
     * @return byte array representation of object.
     */
    public static byte[] serializeObject(final Object obj) {
        try {
            final ByteArrayOutputStream b = new ByteArrayOutputStream();
            final ObjectOutputStream o = new ObjectOutputStream(b);
            o.writeObject(obj);
            return b.toByteArray();
        } catch (IOException ioException) {
            systemRecorder.recordSecurityEvent("Certificate Management Service", "serialization of object", " Some issue occured when serializing keypair object", "CERTIFICATE.GENERATE_CERTIFICATE",
                    ErrorSeverity.ERROR, "FAILURE");
            logger.error(ErrorMessages.INVALID_OBJECT_FOR_SERIALIZATION, ioException);
            throw new IllegalArgumentException(ErrorMessages.INVALID_OBJECT_FOR_SERIALIZATION);
        }
    }

    /**
     * Converts byte array to {@link KeyPair} object.
     * 
     * @param bytes
     *            bytes containing the keyPair object.
     * @return Object form of the byte array given.
     */
    public static Object deSerializeObject(final byte[] bytes) {
        try {
            final ByteArrayInputStream b = new ByteArrayInputStream(bytes);
            final ObjectInputStream o = new ObjectInputStream(b);
            return o.readObject();

        } catch (ClassNotFoundException classNotFoundException) {
            systemRecorder.recordSecurityEvent("Certificate Management Service", "deserialization of object", " Some issue occured when deserializing keypair object",
                    "CERTIFICATE.GENERATE_CERTIFICATE", ErrorSeverity.ERROR, "FAILURE");
            logger.error(ErrorMessages.CLASS_NOT_FOUND_FOR_DESERIALIZATION, classNotFoundException);
            throw new IllegalArgumentException(ErrorMessages.CLASS_NOT_FOUND_FOR_DESERIALIZATION);
        } catch (IOException ioException) {
            systemRecorder.recordSecurityEvent("Certificate Management Service", "deserialization of object", " Some issue occured when deserializing keypair object",
                    "CERTIFICATE.GENERATE_CERTIFICATE", ErrorSeverity.ERROR, "FAILURE");
            logger.error(ErrorMessages.INVALID_OBJECT_FOR_DESERIALIZATION, ioException);
            throw new IllegalArgumentException(ErrorMessages.INVALID_OBJECT_FOR_DESERIALIZATION);
        }
    }
}
