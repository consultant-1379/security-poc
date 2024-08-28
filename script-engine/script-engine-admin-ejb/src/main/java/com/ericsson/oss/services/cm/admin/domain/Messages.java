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

import java.util.IllegalFormatException;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public enum Messages {

    VALIDATION_DATA_SET_INVALID("failure.validation.data-set.invalid"),
    VALIDATION_STRING_TOO_SHORT("failure.validation.string.too-short"),
    VALIDATION_STRING_TOO_LONG("failure.validation.string.too-long"),
    VALIDATION_STRING_EMPTY("failure.validation.string.empty"),
    VALIDATION_AUTH_PROTOCOL_NOT_NONE("failure.validation.auth-protocol.not-none"),
    VALIDATION_PRIV_PROTOCOL_NOT_NONE("failure.validation.priv-protocol.not-none"),
    VALIDATION_PARM_LENGTH_ERROR("failure.validation.parm-length.error"),
    UPDATE_PARAMETER_SUCCESS("success.update.parameter");


    private static final ResourceBundle bundle = ResourceBundle.getBundle("Messages");

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private String key;

    Messages(final String key) {
        this.key = key;
    }

    public String format(final String... parameters) {
        try {
            return String.format(bundle.getString(this.key), (Object[]) parameters);
        } catch (MissingResourceException | ClassCastException | IllegalFormatException exception) {
            logger.warn("Cannot find message for key: " + this.key, exception);
            return "";
        }
    }

    @Override
    public String toString() {
        return this.format();
    }
}
