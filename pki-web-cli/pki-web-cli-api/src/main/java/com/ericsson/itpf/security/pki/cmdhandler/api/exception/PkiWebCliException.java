/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.itpf.security.pki.cmdhandler.api.exception;

import javax.ejb.ApplicationException;

/**
 * Base exception for all PKI CLI services.
 *
 * @author xsumnan on 29/03/2015.
 */
@ApplicationException(rollback = true)
public abstract class PkiWebCliException extends RuntimeException {
    private static final long serialVersionUID = -5164326722913363644L;

    private String suggestedSolution = PkiErrorCodes.CONSULT_ERROR_LOGS;

    public static final int ERROR_CODE_START_INT = 11000;

    public PkiWebCliException() {
    }

    public PkiWebCliException(final String message) {
        super(message);
    }

    public PkiWebCliException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public PkiWebCliException(final Throwable cause) {
        super(cause);
    }

    /**
     * @return error code of the exception
     */
    public int getErrorCode() {
        return ERROR_CODE_START_INT + getErrorType().toInt();
    }

    /**
     * Each subclass of PKIServiceException has it's own ErrorType
     *
     * @return the Error type
     */
    public abstract ErrorType getErrorType();

    /**
     * Gets the proposed solution for this error.
     *
     * @return String with the proposed solution or empty String.
     */
    public String getSuggestedSolution() {
        return suggestedSolution;
    }

    /**
     * Sets the proposed solution for this exception.
     *
     * @param suggestedSolution
     *            String of the proposed solution
     * @return this instance
     */
    public PkiWebCliException setSuggestedSolution(final String suggestedSolution) {
        this.suggestedSolution = suggestedSolution == null ? "" : suggestedSolution;
        return this;
    }

    /**
     * <p>
     * Convenience method to set proposed solution.
     * </p>
     * <p>
     * Internally this method call String.format(suggestedSolution, args)
     * </p>
     *
     * @param suggestedSolution
     *            Suggested solution message. You can use any valid String.format placeholder.
     * @param args
     *            arguments so be placed at the placeholders.
     * @return this instance
     */
    public PkiWebCliException setSuggestedSolution(final String suggestedSolution, final Object... args) {
        return setSuggestedSolution(String.format(suggestedSolution, args));
    }

    /**
     * Convenience method to subclasses so the can easily create messages with the format 'message part1 : message part2'
     *
     * @param part1
     * @param part2
     * @return formatted message
     */
    protected static String formatMessage(final String part1, final String part2) {
        return String.format("%s : %s", part1, part2);
    }

    /**
     * Enumeration of all error types reported by PKI.
     * <p>
     * Each element should be used by ONE subclass of PKIServiceException in order to allow proper handling of error codes.
     * </p>
     */
    public enum ErrorType {

        UNDEFINED(0), UNSUPPORTED_COMMAND_ARGUMENT_ERROR(0), MISSING_MANDATORY_ATTRIBUTE_ERROR(0), KEYSIZE_FORMAT_ERROR(3), ALGO_NAME_NULL_EMPTY(4), COMMAND_SYNTAX_ERROR(1), INVALID_FILE_CONTENT(13), UNEXPECTED_ERROR(
                99), COMMAND_HANDLER_NOT_FOUND_ERROR(99), UNEXPECTED_COMMAND_TYPE(99),
        /*
         * ======= INVALID_INPUT_XML_FILE(101), INVALID_ARGUMENT_ERROR(102), INTERNAL_SERVICE_EXCEPTION(002), PKICONFIG_ERROR(007), ALGO_NOT_FOUND(006), COMMON_RUNTIME_ERROR(101),
         * PROFILE_ALREADY_EXISTS(104), CA_NOT_FOUND( 107), PROFILE_NOT_FOUND(103), NO_PROFILE_OF_GIVEN_TYPE(105), NO_PROFILE_FOUND_MATCHING_CRITERIA(106), PROFILE_IN_USE(108),
         * ENTITY_ALREADY_EXISTS(203), ENTITY_NOT_FOUND(202), ENTITY_IN_USE( 206), ENTITY_NOT_FOUND_LIST(205), NO_ENTITY_FOUND_MATCHING_CRITERIA(204), ENTITY_SERVICE_EXCEPTION(207),
         * CERTIFICATE_NOT_FOUND(308), EXCEPTION_IN_CERTIFICATE_GENERATION(305), CERTIFICATE_ALREADY_EXISTS(306), CSR_GENERATION_EXCEPTION( 307), CERTIFICATE_STATUS_NOT_SUPPORTED(302),
         * INVALID_CSR_FILE(401), ENTITY_CERTIFICATE_NOT_FOUND(404) >>>>>>> bulk update/delete and CAhierarchy
         */

        INVALID_INPUT_XML_FILE(101), INVALID_ARGUMENT_ERROR(102), INTERNAL_SERVICE_EXCEPTION(002), PKICONFIG_ERROR(007), ALGO_NOT_FOUND(006), COMMON_RUNTIME_ERROR(101), PROFILE_ALREADY_EXISTS(104), CA_NOT_FOUND(
                107), PROFILE_NOT_FOUND(103), NO_PROFILE_OF_GIVEN_TYPE(105), NO_PROFILE_FOUND_MATCHING_CRITERIA(106), PROFILE_IN_USE(108), ENTITY_ALREADY_EXISTS(203), ENTITY_NOT_FOUND(202), ENTITY_IN_USE(
                206), ENTITY_NOT_FOUND_LIST(205), NO_ENTITY_FOUND_MATCHING_CRITERIA(204), CERTIFICATE_NOT_FOUND(308), EXCEPTION_IN_CERTIFICATE_GENERATION(305), CERTIFICATE_ALREADY_EXISTS(306), CSR_GENERATION_EXCEPTION(
                307), CERTIFICATE_STATUS_NOT_SUPPORTED(302), INVALID_CSR_FILE(401), ENTITY_CERTIFICATE_NOT_FOUND(404),

        RUNTIME_EXCEPTION(50), PKI_BASE_EXCEPTION(51),

        PROFILE_EXCEPTION(100), PROFILE_SERVICE_EXCEPTION(101), PROFILE_ALREADY_EXIST_EXCEPTION(102), PROFILE_NOT_FOUND_EXCEPTION(103), PROFILE_INUSE_EXCEPTION(104), INVALID_PROFILE_EXCEPTION(105), INVALID_PROFILE_ATTRIBUTE_EXCEPTION(
                106),

        ENTITY_EXCEPTION(200), ENTITY_SERVICE_EXCEPTION(201), ENTITY_ALREADY_EXIST_EXCEPTION(202), ENTITY_NOT_FOUND_EXCEPTION(203), ENTITY_INUSE_EXCEPTION(204), INVALID_ENTITY_EXCEPTION(205), INVALID_ENTITY_ATTRIBUTE_EXCEPTION(
                206), ENTITY_CATEGORY_EXCEPTION(210), ENTITY_CATEGORY_NOT_FOUND_EXCEPTION(211), ENTITY_CATEGORY_ALREADY_EXIST_EXCEPTION(212), ENTITY_CATEGORY_INUSE_EXCEPTION(213), INVALID_ENTITY_CATEGORY_EXCEPTION(
                214), CA_ENTITY_EXCEPTION(220), CA_NOT_FOUND_EXCEPTION(221), INVALID_CA_EXCEPTION(222), END_ENTITY_EXCEPTION(230), OTP_EXCEPTION(240), OTP_EXPIRED_EXCEPTION(241), OTP_NOT_SET_EXCEPTION(
                242),

        SECURITY_EXCEPTION(300), KEYPAIR_GENERATION_EXCEPTION(302), CERTIFICATE_REQUEST_EXCEPTION(310), CERTIFICATE_REQUEST_GENERATION_EXCEPTION(311), INVALID_CERTIFICATE_REQUEST_EXCEPTION(312), CERTIFICATE_EXCEPTION(
                320), CERTIFICATE_SERVICE_EXCEPTION(321), CERTIFICATE_GENERATION_EXCEPTION(322), CERTIFICATE_NOT_FOUND_EXCEPTION(323), CERTIFICATE_REVOKED_EXCEPTION(324), CERTIFICATE_ALREADY_EXIST_EXCEPTION(
                325), CERTIFICATE_FIELD_EXCEPTION(330), UNSUPPORTED_CERTIFICATE_VERSION(331), MISSING_MANDATORYFIELD_EXCEPTION(332), SERIALNUMBER_NOT_FOUND_EXCEPTION(333), INVALID_SUBJECT_EXCEPTION(
                334), CERTIFICATE_EXTENTION_EXCEPTION(340), INVALID_BASIC_CONSTRAINS_EXCEPTION(341), INVALID_AUTHORITYINFORMATIONACCES_EXCEPTION(342), INVALID_AUTHORITYKEYIDENTIFIER_EXCEPTION(343), INVALID_SUBJECTKEYIDENTIFIER_EXCEPTION(
                344), INVALID_SUBJECTALTNAME_EXCEPTION(345), INVALID_KEYUSAGE_EXCEPTION(346), INVALID_EXTENDED_KEYUSAGE_EXCEPTION(347), INVALID_CRLDISTRIBUTIONPOINT_EXCEPTION(348), INVALID_CRL_EXTENSION(
                349), INVALID_CRL_GENERATION_INFO(350), UNSUPPORTED_CRL_VERSION(351), CRLGENERATION_INFO_NOT_FOUND(352),

        PKI_CONFIGURATION_EXCEPTION(400), PKI_CONFIGURATION_SERVICE_EXCEPTION(400), ALGORITHM_EXCEPTION(410), ALGORITHM_NOT_FOUND_EXCEPTION(411), INVALID_ALGORITHM_CATEGORY_EXCEPTION(412),

        EXTCANOTFOUND(501), EXTCANAME_MISMATCH(502), EXTCACERTIFICATE_ALREADY_EXISTS(503), CANAME_IS_NOT_EXTERNAL(504), NETWORK_PROBLEM_FOR_EXTERNAL_CRL(505), EXTCA_USED_IN_TRUSTPROFILE(506), EXTCA_CERTIFICATE_FILE_BAD_FORMAT(
                507),

        REVOCATION_REASON_NOT_SUPPORTED(601), ROOT_CA_CANNOT_REVOKED_CERTIFICATE(602), CERTIFICATE_EXPIRED(603), CERTIFICATE_ALREADY_REVOKED_EXCEPTION(604), ISSUER_CERTIFICATE_REVOKED_EXCEPTION(605), ISSUER_NOT_FOUND_EXCEPTION(

        606), INVALID_DATE_FORMAT_EXCEPTION(607), CRL_NOT_FOUND_EXCEPTION(608), INVALID_CERTIFICATE_STATUS_EXCEPTION(609), HOST_NOT_FOUND_EXCEPTION(610), INVALID_OPERATION_EXCEPTION(611), CRL_ISSUER_NOT_FOUND_EXCEPTION(
                612), INVALID_CERTIFICATE(613), INVALID_CSR_EXCEPTION(615), INVALID_DATE(616), REVOCATION_SERVICE_EXCEPTION(617);

        /**
         * Get the String value of this ErrorType
         *
         * @return errorCode
         */

        private int errorCode;

        private ErrorType(final int errorCode) {
            this.errorCode = errorCode;
        }

        /**
         * Get the integer value of this ErrorType
         *
         * @return errorCode
         */
        public int toInt() {
            return this.errorCode;
        }

        /**
         * Get the String value of this ErrorType
         *
         * @return errorCode
         */
        @Override
        public String toString() {
            return String.valueOf(this.errorCode);
        }

    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof PkiWebCliException)) {
            return false;
        }

        final PkiWebCliException that = (PkiWebCliException) o;

        return getErrorCode() == that.getErrorCode();
    }

    @Override
    public int hashCode() {
        return getErrorType().hashCode();
    }
}
