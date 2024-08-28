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

import com.ericsson.oss.services.cm.admin.domain.SnmpData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ParameterValueSnmpConverter implements ParameterValueConverter {

    private final Logger logger = LoggerFactory.getLogger(ParameterValueSnmpConverter.class);

    private static final ParameterValueConverter instance = new ParameterValueSnmpConverter();
    private static final String ARRAY_START_BRACKET = "\\[";
    private static final String ARRAY_END_BRACKET = "\\]";
    private static final String DOUBLE_QUOTE = "\"";

    public static ParameterValueConverter getInstance() {
        return instance;
    }

    @Override
    public String convert(FilterContext filterContext) {
        try {
            String pibParameterResponseValue = filterContext.getParameterValue();
            pibParameterResponseValue = pibParameterResponseValue.replaceFirst(ARRAY_START_BRACKET, "")
                    .replaceFirst(ARRAY_END_BRACKET, "").replaceAll(DOUBLE_QUOTE, "");
            SnmpData snmpData = new SnmpData(pibParameterResponseValue.split(","));
            return snmpData.toDecryptString(filterContext.getPasswordDecoder());
        } catch (Exception e) {
            logger.error("Failed in SNMPData conversion for parameter:{} error:{}", filterContext.getParameterName(), e.getMessage());
            return null;
        }
    }
}
