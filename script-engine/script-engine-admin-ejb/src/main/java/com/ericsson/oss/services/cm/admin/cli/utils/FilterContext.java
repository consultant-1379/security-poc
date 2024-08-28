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
package com.ericsson.oss.services.cm.admin.cli.utils;

import com.ericsson.oss.services.cm.admin.cli.manager.ParameterManager;

import java.util.function.Function;

public class FilterContext {

    private String parameterName;
    private String parameterValue;
    private ParameterManager parameterManager;
    private Function<String, String> passwordDecoder;

    public FilterContext(String parameterName, String parameterValue, ParameterManager parameterManager, Function<String, String> passwordDecoder) {
        this.parameterName = parameterName;
        this.parameterValue = parameterValue;
        this.parameterManager = parameterManager;
        this.passwordDecoder = passwordDecoder;
    }

    public Function<String, String> getPasswordDecoder() {
        return passwordDecoder;
    }

    public String getParameterName() {
        return parameterName;
    }

    public String getParameterValue() {
        return parameterValue;
    }

    public ParameterManager getParameterManager() {
        return parameterManager;
    }
}
