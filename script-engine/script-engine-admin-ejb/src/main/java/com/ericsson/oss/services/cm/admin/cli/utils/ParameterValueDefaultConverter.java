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

import java.util.Optional;

public class ParameterValueDefaultConverter implements ParameterValueConverter {

    private static final ParameterValueConverter instance = new ParameterValueDefaultConverter();

    public static ParameterValueConverter getInstance() {
        return instance;
    }

    @Override
    public String convert(FilterContext filterContext) {
        String value = Optional.ofNullable(filterContext.getParameterValue())
                .filter(parameterValue -> parameterValue.contains("[") && parameterValue.contains("]"))
                .map(parameterValue -> parameterValue.replace("\"", ""))
                .orElse(filterContext.getParameterValue());

        return Optional.ofNullable(value)
                .filter(parameterValue -> parameterValue.contains(":"))
                .map(parameterValue -> parameterValue.replaceAll("\\[", "{").replaceAll("\\]", "}"))
                .orElse(value);
    }
}
