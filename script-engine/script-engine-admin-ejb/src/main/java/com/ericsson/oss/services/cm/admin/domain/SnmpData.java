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
package com.ericsson.oss.services.cm.admin.domain;

import static java.util.stream.Collectors.joining;
import static java.util.stream.Collectors.toList;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.apache.commons.lang.StringUtils;

import com.ericsson.oss.services.cm.admin.validation.ValidationResult;
import com.google.common.collect.ImmutableList;

public class SnmpData {
    private static final ImmutableList<String> FIELD_NAMES = ImmutableList.of("securityLevel", "authProtocol", "authPassword", "privProtocol",
            "privPassword", "user");
    private static final List<String> SUPPORTED_SECUTIRY_LEVEL = Arrays.asList("NO_AUTH_NO_PRIV", "AUTH_PRIV", "AUTH_NO_PRIV");
    private static final List<String> SUPPORTED_AUTH_PROTOCOL = Arrays.asList("NONE", "MD5", "SHA1");
    private static final List<String> SUPPORTED_PRIV_PROTOCOL = Arrays.asList("NONE", "DES", "AES128");
    private static final char FIELD_DELIMITER = ',';
    private static final int MIN_KEY_LENGTH = 8;
    private static final int MIN_USER_LENGTH = 1;
    private static final int MAX_USER_LENGTH = 20;

    private String snmpSecurityLevel;
    private String snmpAuthenticationProtocol;
    private String snmpPrivacyProtocol;
    private String snmpAuthenticationPassword;
    private String snmpPrivacyPassword;
    private String user;

    public SnmpData(final String[] snmpData) {
        if (snmpData.length < FIELD_NAMES.size()) {
            return;
        }
        final Map<String, String> parmValueMap = new CaseInsensitiveMap(
                Arrays.asList(snmpData).stream().map(field -> field.split(":", 2))
                        .collect(Collectors.toMap(data -> data[0].trim(), data -> data[1] == null ? "" : data[1].trim())));

        this.snmpSecurityLevel = parmValueMap.get("securityLevel") == null ? "" : parmValueMap.get("securityLevel").toUpperCase();
        this.snmpAuthenticationPassword = parmValueMap.get("authPassword") == null ? "" : parmValueMap.get("authPassword");
        this.snmpAuthenticationProtocol = parmValueMap.get("authProtocol") == null ? "" : parmValueMap.get("authProtocol").toUpperCase();
        this.snmpPrivacyPassword = parmValueMap.get("privPassword") == null ? "" : parmValueMap.get("privPassword");
        this.snmpPrivacyProtocol = parmValueMap.get("privProtocol") == null ? "" : parmValueMap.get("privProtocol").toUpperCase();
        this.user = parmValueMap.get("user") == null ? "" : parmValueMap.get("user");

    }

    public SnmpData(final String snmpSecurityLevel, final String snmpAuthenticationProtocol, final String snmpAuthenticationPassword,
                    final String snmpPrivacyProtocol, final String snmpPrivacyPassword, final String user) {
        this.snmpSecurityLevel = snmpSecurityLevel.toUpperCase();
        this.snmpAuthenticationPassword = snmpAuthenticationPassword.trim();
        this.snmpAuthenticationProtocol = snmpAuthenticationProtocol.trim().toUpperCase();
        this.snmpPrivacyPassword = snmpPrivacyPassword.trim();
        this.snmpPrivacyProtocol = snmpPrivacyProtocol.trim().toUpperCase();
        this.user = user.trim();
    }

    public String getSnmpSecurityLevel() {
        return snmpSecurityLevel;
    }

    public String getSnmpAuthenticationProtocol() {
        return snmpAuthenticationProtocol;
    }

    public String getSnmpPrivacyProtocol() {
        return snmpPrivacyProtocol;
    }

    public String getSnmpAuthenticationPassword() {
        return snmpAuthenticationPassword;
    }

    public String getSnmpPrivacyPassword() {
        return snmpPrivacyPassword;
    }

    public String getUser() {
        return user;
    }

    @Override
    public String toString() {
        return "{"
                + zipStringLists(FIELD_NAMES.stream().map(header -> header + ":").collect(toList()), detailToStrings()).stream().collect(joining(","))
                + "}";
    }

    private List<String> detailToStrings() {
        return ImmutableList.of(this.snmpSecurityLevel, this.snmpAuthenticationProtocol, this.snmpAuthenticationPassword, this.snmpPrivacyProtocol,
                this.snmpPrivacyPassword, this.user);
    }

    private List<String> zipStringLists(final List<String> first, final List<String> second) {
        final Iterator<String> itFirst = first.iterator();
        final Iterator<String> itSecond = second.iterator();
        final ArrayList<String> result = new ArrayList<>();
        while (itFirst.hasNext() && itSecond.hasNext()) {
            final String key = itFirst.next();
            final String value = itSecond.next();
            result.add(key + value);
        }
        return result;
    }

    public ValidationResult validate() {
        ValidationResult result = validateDataInList(SUPPORTED_SECUTIRY_LEVEL, snmpSecurityLevel, "securityLevel")
                .and(validateDataInList(SUPPORTED_AUTH_PROTOCOL, snmpAuthenticationProtocol, "authProtocol"))
                .and(validateDataInList(SUPPORTED_PRIV_PROTOCOL, snmpPrivacyProtocol, "privProtocol"));
        if (result.isNotValid()) {
            return result;
        }

        if ("NO_AUTH_NO_PRIV".equals(snmpSecurityLevel)) {
            return result.and(validateStringLength(user, "user", MIN_USER_LENGTH, MAX_USER_LENGTH));
        }

        if (!"NO_AUTH_NO_PRIV".equals(snmpSecurityLevel)) {
            if ("NONE".equals(snmpAuthenticationProtocol)) {
                return ValidationResult.fail(Messages.VALIDATION_AUTH_PROTOCOL_NOT_NONE.toString());
            } else {
                result = result.and(validateStringLength(this.snmpAuthenticationPassword, "authPassword", MIN_KEY_LENGTH, 0));
            }
        }

        if ("AUTH_PRIV".equals(snmpSecurityLevel) && "NONE".equals(snmpPrivacyProtocol)) {
            return ValidationResult.fail(Messages.VALIDATION_PRIV_PROTOCOL_NOT_NONE.toString());
        }

        if ("AUTH_NO_PRIV".equals(snmpSecurityLevel)) {
            return result.and(validateStringLength(user, "user", MIN_USER_LENGTH, MAX_USER_LENGTH));
        }

        if (!"NONE".equals(snmpPrivacyProtocol)) {
            result = result.and(validateStringLength(this.snmpPrivacyPassword, "privPassword", MIN_KEY_LENGTH, 0));
        }

        return result.and(validateStringLength(user, "user", MIN_USER_LENGTH, MAX_USER_LENGTH));
    }

    private ValidationResult validateStringLength(final String filedValue, final String fieldName, final int minlength, final int maxlength) {
        if (StringUtils.isBlank(filedValue)) {
            return ValidationResult.fail(Messages.VALIDATION_STRING_EMPTY.format(fieldName));
        }
        if ((maxlength > minlength) && (filedValue.length() > maxlength)) {
            return ValidationResult.fail(Messages.VALIDATION_STRING_TOO_LONG.format(fieldName, String.valueOf(maxlength)));
        }
        return filedValue.length() < minlength
                ? ValidationResult.fail(Messages.VALIDATION_STRING_TOO_SHORT.format(fieldName, String.valueOf(minlength)))
                : ValidationResult.ok(filedValue);
    }

    private ValidationResult validateDataInList(final List<String> dataList, final String fieldValue, final String fieldName) {
        if (!dataList.contains(fieldValue)) {
            return ValidationResult.fail(Messages.VALIDATION_DATA_SET_INVALID.format(fieldName, dataList.toString()));
        }
        return ValidationResult.ok(fieldValue);
    }

    public String toDecryptString(final Function<String, String> passwordDecoder) {
        if (StringUtils.isNotBlank(this.snmpAuthenticationPassword)) {
            this.snmpAuthenticationPassword = passwordDecoder.apply(this.snmpAuthenticationPassword);
        }
        if (StringUtils.isNotBlank(this.snmpPrivacyPassword)) {
            this.snmpPrivacyPassword = passwordDecoder.apply(this.snmpPrivacyPassword);
        }
        return toString();
    }

    public static int getFieldnumber() {
        return FIELD_NAMES.size();
    }

    public static char getDelimiter() {
        return FIELD_DELIMITER;
    }
}
