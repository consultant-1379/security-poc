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
package com.ericsson.oss.services.cm.admin.validation;

import javax.inject.Inject;

import org.apache.commons.lang3.StringUtils;

import com.ericsson.oss.services.cm.admin.domain.Messages;
import com.ericsson.oss.services.cm.admin.domain.SnmpData;
import com.ericsson.oss.services.cm.admin.utility.SnmpDataHelper;

import java.util.Arrays;

public class ParametersValidationFactory {

    @Inject
    private SnmpDataHelper snmpDataHelper;

    public ValidationResult validateSnmpData(final String parmValue) {
        if (StringUtils.countMatches(parmValue, SnmpData.getDelimiter()) != SnmpData.getFieldnumber() - 1) {
            return ValidationResult.fail(Messages.VALIDATION_PARM_LENGTH_ERROR.toString());
        }

        final SnmpData data = snmpDataHelper.from(parmValue);

        if (data != null) {
            final ValidationResult validationResult = data.validate();
            if (validationResult.isValid()) {
                validationResult.setValue(snmpDataHelper.toParmValueString(data));
            }
            return validationResult;
        }
        return ValidationResult.fail("");
    }

    public ValidationResult validateAuditTime(final String parmValue) {
        if (StringUtils.isNoneBlank(parmValue)) {
            final String[] auditTime = parmValue.split(":");
            if (auditTime.length == 2) {
                try {
                    int minute = Integer.parseUnsignedInt(auditTime[1]);
                    final int hour = (Integer.parseUnsignedInt(auditTime[0]) + minute / 60) % 24;
                    minute = minute % 60;

                    return ValidationResult.ok(String.format("%02d:%02d", hour, minute));
                } catch (final NumberFormatException e) {
                    return ValidationResult.fail("");
                }
            }
        }
        return ValidationResult.fail("");
    }

    public ValidationResult validateData(final String paramValue) {
        // List params
        if (paramValue.startsWith("[") && paramValue.endsWith("]")) {
            if (containsUnescapedQuotes(paramValue.substring(1, paramValue.length() - 1))) {
                return ValidationResult.fail("Values cannot contain unescaped quotes.");
            }

            return ValidationResult.ok(paramValue.substring(1, paramValue.length() - 1));
        }

        // Key-value params
        else if (paramValue.contains(":")) {
            return handleObjectTypeParams(paramValue);
        }

        // Reject non-square brackets multiple-values
        else if (paramValue.contains(",")) {
            return ValidationResult.fail("Encase multiple-value parameters in square brackets.");
        }

        // Single value params
        if (containsUnescapedQuotes(paramValue)) {
            return ValidationResult.fail("Values cannot contain unescaped quotes.");
        }
        if (paramValue.startsWith("{") || paramValue.endsWith("}")) {
            return ValidationResult.fail("Object-type parameters must have key-value pairs.");
        }

        return ValidationResult.ok(paramValue);
    }

    private boolean containsUnescapedQuotes(String values) {
        return Arrays.stream(values.split(",")).anyMatch(value -> value.contains("\"") && !value.contains("\\\""));
    }

    private ValidationResult handleObjectTypeParams(String paramValue) {
        if (!paramValue.startsWith("{") || !paramValue.endsWith("}")) {
            return ValidationResult.fail("Key-value type parameters must be encased in curly brackets.");
        }

        if (containsUnescapedQuotes(paramValue.substring(1, paramValue.length() - 1))) {
            return ValidationResult.fail("Values cannot contain unescaped quotes.");
        }

        if (paramValue.charAt(paramValue.length() - 2) == ':') {
            return ValidationResult.fail("Missing value.");
        }

        return ValidationResult.ok(paramValue.substring(1, paramValue.length() - 1));
    }
}
