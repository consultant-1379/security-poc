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
import com.ericsson.oss.services.cm.admin.domain.SnmpData;

import java.util.HashMap;
import java.util.Map;

public final class ParameterValueMapper {

    private static final Map<Class, ParameterValueConverter> parameterValueMapperByClass = new HashMap<>();

    static {
        parameterValueMapperByClass.put(SnmpData.class, ParameterValueSnmpConverter.getInstance());
        parameterValueMapperByClass.put(null, ParameterValueDefaultConverter.getInstance());
        parameterValueMapperByClass.put(String.class, ParameterValueDefaultConverter.getInstance());
    }

    private ParameterValueMapper() {
    }

    public static ParameterValueConverter getSuitableConverter(FilterContext filterContext) {
        ParameterManager parameterManager = filterContext.getParameterManager();
        if (!parameterManager.isPasswordParameter(filterContext.getParameterName())) {
            return ParameterValueDefaultConverter.getInstance();
        } else {
            Class dataType = parameterManager.getDataType(filterContext.getParameterName());
            return parameterValueMapperByClass.get(dataType);
        }
    }

}
