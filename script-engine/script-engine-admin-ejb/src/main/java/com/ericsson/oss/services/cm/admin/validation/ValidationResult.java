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

import java.util.Objects;


public class ValidationResult {
    private final Boolean valid;
    private String errorMessage;
    private String value;

    /**
     * Returns information if validation result is valid
     *
     * @return Result true if valid or false if not valid
     */
    public boolean isValid() {
        return valid;
    }

    /**
     * Returns information if validation result is not valid
     *
     * @return Result true if not valid or false if valid
     */
    public boolean isNotValid() {
        return !valid;
    }

    /**
     * @param valid
     * @param errorMessage
     * @param value
     */

    public ValidationResult(final Boolean valid, final String errorMessage, final String value) {
        this.valid = valid;
        this.errorMessage = errorMessage;
        this.value = value;
    }

    /**
     * @return errorMessage
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * @param errorMessage
     */
    public void setErrorMessage(final String errorMessage) {
        this.errorMessage = errorMessage;
    }

    /**
     * @return value
     */
    public String getValue() {
        return value;
    }

    /**
     * @param value
     */
    public void setValue(final String value) {
        this.value = value;
    }

    /**
     * @param result
     * @return
     */
    public ValidationResult and(final ValidationResult result) {
        if (!valid) {
            return this;
        } else {
            return result;
        }
    }

    /**
     * @param result
     * @return
     */
    public ValidationResult or(final ValidationResult result) {
        if (valid) {
            return this;
        } else {
            return result;
        }
    }

    /**
     * Generates predefined success validation result
     *
     * @param value
     * @return Success validation result
     */
    @SuppressWarnings("PMD.ShortMethodName")
    public static ValidationResult ok(final String value) {
        return new ValidationResult(true, null, value);
    }

    /**
     * Generates predefined failure validation result
     *
     * @param errorMessage
     *
     * @return Failure validation result with errorMessage taken for provided one
     */
    public static ValidationResult fail(final String errorMessage) {
        return new ValidationResult(false, errorMessage, null);
    }

    @Override
    public int hashCode() {
        return Objects.hash(valid, errorMessage, value);
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        final ValidationResult result = (ValidationResult) obj;

        return Objects.equals(valid, result.valid) &&
                Objects.equals(errorMessage, result.errorMessage) &&
                Objects.equals(value, result.value);
    }

    @Override
    public String toString() {
        return "ValidationResult{valid=" + valid + ", errorMessage='" + errorMessage + '\'' + ", value='" + value + '\'' + '}';
    }


}
