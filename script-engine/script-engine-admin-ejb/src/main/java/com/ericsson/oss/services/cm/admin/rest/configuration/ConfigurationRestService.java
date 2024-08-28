/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.admin.rest.configuration;

import com.ericsson.oss.services.cm.admin.domain.ConfigurationParameter;
import com.ericsson.oss.services.cm.admin.rest.client.common.ResponseErrorDetails;
import com.ericsson.oss.services.cm.admin.rest.client.common.RestRequest;
import com.ericsson.oss.services.cm.admin.utility.ConfigurationServiceHelper;
import com.ericsson.oss.services.cm.admin.utility.PasswordHelper;
import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.entity.ContentType;

import javax.inject.Inject;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static com.ericsson.oss.services.cm.admin.rest.client.RestUrls.*;
import static com.ericsson.oss.services.cm.admin.rest.client.common.HttpMethods.GET;
import static com.ericsson.oss.services.cm.admin.rest.client.common.RestResponse.getDefaultResponseHandler;
import static com.ericsson.oss.services.cm.admin.utility.ConfigurationServiceHelper.*;

public class ConfigurationRestService implements ConfigurationService {

    @Inject
    private PasswordHelper passwordHelper;

    @Inject
    private ConfigurationServiceHelper configurationServiceHelper;

    private static final String ENCRYTPTED_PIB_USERNAME = "AzxSleCuuIWaBhXs9gygGf+Ba8mtHnsMi38A006STQk=";
    private static final String ENCRYTPTED_PIB_SECRETE = "3XIyvj7sMfYqs/hROb8BumzmCRhJMyWr96CDSjSS1v8=";

    public ConfigurationRestService() {
        // No-arg constructor required by application server
    }

    @Override

    public String getParameter(ConfigurationParameterFilterCriteria configurationParameterFilterCriteria) {
        ConfigurationParameter configurationParameter = configurationParameterFilterCriteria.getConfigurationParameter();
        StringBuilder restUrl = new StringBuilder(CONFIGURATION_SERVICE_GET_PIB.getFullUrl()).append(configurationParameter.getName());
        if(configurationParameter.getServiceIdentifier() != null)
        {
            restUrl.append("&").append(SERVICE_IDENTIFIER_PIB_API_KEYWORD).append("=").append(configurationParameter.getServiceIdentifier());
        }
        if(configurationParameter.getJvmIdentifier() != null)
        {
            restUrl.append("&").append(JVM_IDENTIFIER_PIB_API_KEYWORD).append("=").append(configurationParameter.getJvmIdentifier());
        }
        return RestRequest.Builder.of(restUrl.toString())
                .setMethod(GET)
                .setEntity(null)
                .setPIBAuthorization("Basic "
                        + Base64.encodeBase64String(
                                (passwordHelper.decryptDecode(ENCRYTPTED_PIB_USERNAME) + ":" + passwordHelper.decryptDecode(ENCRYTPTED_PIB_SECRETE))
                                        .getBytes()))
                .build()
                .send(getDefaultResponseHandler(String.class, ResponseErrorDetails.class))
                .ifFailure(this::failureHandler)
                .getData()
                .orElse(null);

    }

    @Override
    public Boolean updateParameter(ConfigurationParameter configurationParameter) {
        try {
            StringBuilder restUrl = new StringBuilder(CONFIGURATION_SERVICE_UPDATE_PIB.getFullUrl())
                    .append(configurationParameter.getName()).append("&").append(PARAM_VALUE_PIB_API_KEYWORD)
                    .append("=").append(URLEncoder.encode(configurationParameter.getValue(), "UTF-8"));
            if(configurationParameter.getServiceIdentifier() != null)
            {
                restUrl.append("&").append(SERVICE_IDENTIFIER_PIB_API_KEYWORD)
                        .append("=").append(configurationParameter.getServiceIdentifier());
            }
            if(configurationParameter.getJvmIdentifier() != null)
            {
                restUrl.append("&").append(JVM_IDENTIFIER_PIB_API_KEYWORD)
                        .append("=").append(configurationParameter.getJvmIdentifier());
            }
            return RestRequest.Builder.of(restUrl.toString())
                    .setMethod(GET)
                    .setEntity(null)
                    .setPIBAuthorization("Basic " + Base64
                            .encodeBase64String((passwordHelper.decryptDecode(ENCRYTPTED_PIB_USERNAME) + ":"
                                    + passwordHelper.decryptDecode(ENCRYTPTED_PIB_SECRETE)).getBytes()))
                    .setContentType(ContentType.APPLICATION_JSON.toString())
                    .build()
                    .send(getDefaultResponseHandler(void.class, ResponseErrorDetails.class))
                    .ifFailure(this::failureHandler)
                    .isValid();
        } catch (UnsupportedEncodingException e) {
            throw new ConfigurationRestServiceException("Problem with url encoder");
        } catch (Exception e) {
            throw e;
        }
    }

    @Override
    public List<ConfigurationParameter> getAllParameter(ConfigurationParameterFilterCriteria configurationParameterFilterCriteria) {
        String restRequestUrl = configurationServiceHelper.getFullUrlForPibApi(configurationParameterFilterCriteria, CONFIGURATION_SERVICE_GET_ALL_GLOBAL_PIB.getFullUrl());
        TypeReference<List<ConfigurationParameter>> entityType = new TypeReference<List<ConfigurationParameter>>() {};
        return RestRequest.Builder.of(restRequestUrl)
                .setMethod(GET)
                .setPIBAuthorization("Basic " + Base64
                        .encodeBase64String((passwordHelper.decryptDecode(ENCRYTPTED_PIB_USERNAME) + ":"
                                + passwordHelper.decryptDecode(ENCRYTPTED_PIB_SECRETE)).getBytes(StandardCharsets.UTF_8)))
                .build()
                .send(getDefaultResponseHandler(entityType, ResponseErrorDetails.class))
                .ifFailure(this::failureHandler)
                .getData()
                .orElse(Collections.emptyList());
    }

    private void failureHandler(final Optional<ResponseErrorDetails> optionalErrorDetails) {
        final ResponseErrorDetails errorDetails = optionalErrorDetails
                .orElseThrow(() -> new ConfigurationRestServiceException("Problem with configuration service"));
        throw new ConfigurationRestServiceException(errorDetails.getMessage());
    }

}