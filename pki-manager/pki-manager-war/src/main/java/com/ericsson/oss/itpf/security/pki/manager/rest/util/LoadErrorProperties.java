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
package com.ericsson.oss.itpf.security.pki.manager.rest.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.rest.dto.ErrorMessageDTO;

/**
 * A utility class to load the Error messages stored in a properties file to a {@link Map}.
 *
 * @author xhemgan
 * @version 1.1.30
 *
 */
@Singleton
public class LoadErrorProperties {

    @Inject
    private ErrorMessageDTO errorMessageDTO;

    private final Map<String, String> propvals = new HashMap<String, String>();
    private final Map<String, String> revocationErrorMap = new HashMap<String, String>();
    private final static String INTERNAL_SERVER_ERROR_ID = "11001";
    private final static String SECURITY_VIOLATION_ERROR_ID = "201041";
    private final static String SECURITY_VIOLATION_EXCEPTION_MESSAGE = "access control decision: denied to invoke";
    private final static String ERROR_MESSAGE_FILE_NAME = "/ErrorMessages.properties";
    private final static String REVOCATION_ERROR_MESSAGE_FILE_NAME = "/RevocationErrorMessages.properties";

    /**
     * Method to load error messages and their respective IDs stored in a properties file to a {@link Map}
     *
     * @throws IOException
     */
    @PostConstruct
    void startup() throws IOException {
        loadErrorMessages(ERROR_MESSAGE_FILE_NAME, propvals);
        loadErrorMessages(REVOCATION_ERROR_MESSAGE_FILE_NAME, revocationErrorMap);
    }

    /**
     * Method to get ID of an error message.
     *
     * @param value
     *            error message
     * @return {@link ErrorMessageDTO} which contains error message and error code
     */
    public ErrorMessageDTO getErrorMessageDTO(final String value) {
        if (value.trim().contains(SECURITY_VIOLATION_EXCEPTION_MESSAGE)) {
            errorMessageDTO.setCode(SECURITY_VIOLATION_ERROR_ID);
            errorMessageDTO.setMessage(propvals.get(SECURITY_VIOLATION_ERROR_ID));
            return errorMessageDTO;
        }
        for (Map.Entry<String, String> entry : propvals.entrySet()) {
            final String key = entry.getKey();
            if (value.trim().contains(propvals.get(key).trim())) {
                errorMessageDTO.setCode(key);
                errorMessageDTO.setMessage(value);
                return errorMessageDTO;
            }
        }

        errorMessageDTO.setCode(INTERNAL_SERVER_ERROR_ID);
        errorMessageDTO.setMessage(propvals.get(INTERNAL_SERVER_ERROR_ID));
        return errorMessageDTO;
    }

    /**
     * Method used to store all error messages in a properties file to a {@link Map}
     *
     * @throws IOException
     */
    private void loadErrorMessages(final String name, final Map<String, String> map) throws IOException {
        final Properties prop = new Properties();
        InputStream input;

        input = LoadErrorProperties.class.getResourceAsStream(name);
        prop.load(input);

        final Set<String> propertyNames = prop.stringPropertyNames();
        for (final String Property : propertyNames) {

            map.put(Property, prop.getProperty(Property));
        }

        input.close();

    }

    /**
     * Method to get ID of an error message.
     *
     * @param message
     *            error message
     * @return ID of the given error message
     */
    public String getRevocationErrorCode(final String message) {
        if (message.trim().contains(SECURITY_VIOLATION_EXCEPTION_MESSAGE)) {
            return SECURITY_VIOLATION_ERROR_ID;
        }
        for (Map.Entry<String, String> entry : revocationErrorMap.entrySet()) {
            final String key = entry.getKey();
            if (message.trim().contains(revocationErrorMap.get(key).trim())) {
                return key;
            }
        }

        return (propvals.get(INTERNAL_SERVER_ERROR_ID));
    }

    /*
     * Method to get ID of an error message.
     * 
     * @param message error message
     * 
     * @return ID of the given error message
     */
    public String getMessage(final String message) {
        if (message.trim().contains(SECURITY_VIOLATION_EXCEPTION_MESSAGE)) {
            return propvals.get(SECURITY_VIOLATION_ERROR_ID);
        }

        return (propvals.get(INTERNAL_SERVER_ERROR_ID));
    }

}
