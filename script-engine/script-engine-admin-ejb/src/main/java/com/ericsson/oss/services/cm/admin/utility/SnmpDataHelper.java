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
package com.ericsson.oss.services.cm.admin.utility;

import java.util.Arrays;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.services.cm.admin.domain.SnmpData;

@Singleton
public class SnmpDataHelper {
    @Inject
    private PasswordHelper passwordHelper;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private String[] decodeString(final String snmpString) {
        if (snmpString.startsWith("{") && snmpString.endsWith("}") && snmpString.length() > 2) {
            return snmpString.substring(1, snmpString.length() - 1).concat(" ").split(",");
        }
        return new String[0];
    }

    public SnmpData from(final String snmpString) {

        final String[] snmpStringArray = decodeString(snmpString);
        if (snmpStringArray.length != SnmpData.getFieldnumber()) {
            return null;
        }
        return from(snmpStringArray);
    }

    public SnmpData from(final String[] snmpStringArray) {
        try{
            if (snmpStringArray != null) {
                if (snmpStringArray.length != SnmpData.getFieldnumber()) {
                    return null;
                }
                if (Arrays.asList(snmpStringArray).stream().filter(StringUtils::isNotBlank).allMatch(field -> field.contains(":"))) {
                    return new SnmpData(snmpStringArray);
                } else {
                    if (Arrays.stream(new int[] { 0, 1, 3, 5 }).noneMatch(index -> snmpStringArray[index].contains(":"))) {
                        return new SnmpData(snmpStringArray[0], snmpStringArray[1], snmpStringArray[2], snmpStringArray[3], snmpStringArray[4],
                                snmpStringArray[5]);
                    }
                }
            }
        } catch (final Exception e) {
            logger.warn("The exception is {}, caused by {}", e.toString(), e.getCause());
            return null;
        }
        return null;
    }

    public String toParmValueString(final SnmpData snmpData){
        return "securityLevel:" + snmpData.getSnmpSecurityLevel()
        + "," + "authPassword:" + passwordHelper.encryptEncode(snmpData.getSnmpAuthenticationPassword())
        + "," + "authProtocol:" + snmpData.getSnmpAuthenticationProtocol()
        + "," + "privPassword:" + passwordHelper.encryptEncode(snmpData.getSnmpPrivacyPassword())
        + "," + "privProtocol:" + snmpData.getSnmpPrivacyProtocol()
        + "," + "user:" + snmpData.getUser();
    }

}