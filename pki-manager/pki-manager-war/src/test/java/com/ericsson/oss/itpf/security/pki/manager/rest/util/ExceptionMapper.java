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

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.rest.dto.ErrorMessageDTO;
import com.ericsson.oss.itpf.security.pki.manager.rest.serializers.ErrorMessagesSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * A base class extended by all the test classes for ExceptionMappers. This has all constants and utility methods required.
 * 
 * @author xhemgan
 * @version 1.1.30
 */
public class ExceptionMapper {

    @Inject
    ErrorMessageDTO errorMessageDTO;

    @Inject
    LoadErrorProperties loadErrorProperties;

    private final static String INTERNA_SERVER_ERROR = "{\"code\":11002,\"message\":\"An unexpected internal system error occurred. Please check logs.\"}";
    protected final static String INVALID_VALIDITY = "Invalid Validity!";

    protected final static int STATUS_BAD_REQUEST = 400;

    /**
     * @param errorMessage
     *            The error message that should be converted to JSON
     * @return the JSON string containing given error message along with its ID
     */
    public String getJSONErrorMessage(final String errorMessage) {

        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();
        String result;

        module.addSerializer(ErrorMessageDTO.class, new ErrorMessagesSerializer());

        mapper.registerModule(module);

        try {
            errorMessageDTO = loadErrorProperties.getErrorMessageDTO(errorMessage);
            result = mapper.writeValueAsString(errorMessageDTO);
        } catch (Exception e) {
            return INTERNA_SERVER_ERROR;
        }
        return result;
    }
}
