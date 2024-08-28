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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile;

import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;

/**
 * This class is used to validate subject fields.
 * 
 * @author tcsvmeg
 * 
 */
public class SubjectValidator {

    @Inject
    Logger logger;

    private final static String EMAIL_REGEX = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";
    private final static String COUNTRY_REGEX = "^[A-Z]{2}$";
    private static final String OVERRIDING_OPERATOR = "?";

    private final static int MAX_ALLOWABLE_LENGTH_64 = 64;
    private final static int MAX_ALLOWABLE_LENGTH_40 = 40;
    private final static int MAX_ALLOWABLE_LENGTH_128 = 128;
    private final static int MAX_ALLOWABLE_LENGTH_16 = 16;
    private final static int MAX_ALLOWABLE_LENGTH_3 = 3;
    private final static int MAX_ALLOWABLE_LENGTH_5 = 5;
    private final static int MAX_ALLOWABLE_LENGTH_255 = 255;

    /**
     * All the Subject Field Types and Values will be retrieved from the given Subject
     * 
     * @param subject
     * @return Nothing
     * @throws InvalidSubjectException
     *             thrown when given subject is not valid.
     */
    public boolean validate(final Subject subject) throws InvalidSubjectException {
        int validSubjectFieldCount = 0;

        final List<SubjectField> subjectFieldList = subject.getSubjectFields();

        for (final SubjectField subjectField : subjectFieldList) {
            final SubjectFieldType subjectFieldType = subjectField.getType();
            String subjectFieldValue = subjectField.getValue();

            if ((!ValidationUtils.isNullOrEmpty(subjectFieldValue))) {
                subjectFieldValue = subjectFieldValue.trim();

                if (ValidationUtils.isValidSubjectString(subjectFieldValue)) {
                    validSubjectFieldCount++;
                } else {
                    validateSubjectValue(subjectFieldType, subjectFieldValue);
                    validSubjectFieldCount++;
                }

                if (Constants.COMMA_SUPPORTED_DN_FIELD_TYPES.contains(subjectField.getType().getValue()) && subjectFieldValue.matches(Constants.UNSUPPORTED_DIRECTORY_STRING_REGEX)) {
                    logger.info("Subject field value {} contains unsupported character (=/\"\\)", subjectFieldValue);
                    throw new InvalidSubjectException(ErrorMessages.UNSUPPORTED_CHARACTERS_FOR_DIRECTORY_STRING_SUBJECT);
                }
                else if (!Constants.COMMA_SUPPORTED_DN_FIELD_TYPES.contains(subjectField.getType().getValue()) && subjectFieldValue.matches(Constants.UNSUPPORTED_CHAR_REGEX)) {
                    logger.info("Subject field value {} contains unsupported character (=/,\"\\)", subjectFieldValue);
                    throw new InvalidSubjectException(ErrorMessages.UNSUPPORTED_CHARACTERS_SUBJECT);
                }
            }
        }

        if (validSubjectFieldCount == 0) {
            return false;
        }

        return true;
    }

    /**
     * This method validates all the fields present in the Subject
     * 
     * @param subjectFieldType
     * @param subjectFieldValue
     * @return Nothing
     */
    public void validateSubjectValue(final SubjectFieldType subjectFieldType, final String subjectFieldValue) throws InvalidSubjectException {
        switch (subjectFieldType) {
        case COMMON_NAME:
        case ORGANIZATION:
        case ORGANIZATION_UNIT:
        case SERIAL_NUMBER:
        case DN_QUALIFIER:
        case TITLE:
            subjectFieldValidation(subjectFieldType.name(), subjectFieldValue);
            break;
        case COUNTRY_NAME:
            validateCountryName(subjectFieldValue);
            break;
        case STATE:
        case LOCALITY_NAME:
            subjectFieldValidation(subjectFieldType.name(), subjectFieldValue, MAX_ALLOWABLE_LENGTH_128);
            break;
        case GIVEN_NAME:
            subjectFieldValidation(subjectFieldType.name(), subjectFieldValue, MAX_ALLOWABLE_LENGTH_16);
            break;
        case SURNAME:
            subjectFieldValidation(subjectFieldType.name(), subjectFieldValue, MAX_ALLOWABLE_LENGTH_40);
            break;
        case STREET_ADDRESS:
            subjectFieldValidation(subjectFieldType.name(), subjectFieldValue, MAX_ALLOWABLE_LENGTH_40);
            break;
        case DC:
            subjectFieldValidation(subjectFieldType.name(), subjectFieldValue, MAX_ALLOWABLE_LENGTH_255);
            break;
        case INITIALS:
            subjectFieldValidation(subjectFieldType.name(), subjectFieldValue, MAX_ALLOWABLE_LENGTH_5);
            break;
        case GENERATION:
            subjectFieldValidation(subjectFieldType.name(), subjectFieldValue, MAX_ALLOWABLE_LENGTH_3);
            break;
        case EMAIL_ADDRESS:
            validateEmailEntries(Arrays.asList(subjectFieldValue));
            break;
        default:
            throw new InvalidSubjectException("Unknown Field Type in Subject " + subjectFieldType);
        }
    }

    /**
     * This method checks whether the input String is ASCII printable or not
     * 
     * @param fieldname
     * @param fieldvalue
     * @param MaximumLength
     * @return Nothing
     */
    public void subjectFieldValidation(final String fieldName, final String fieldValue, final int maxLength) throws InvalidSubjectException {

        if (fieldValue.length() > maxLength) {
            throw new InvalidSubjectException(fieldName + " length should be under " + maxLength);
        }

        if (!ValidationUtils.isAsciiPrintable(fieldValue)) {
            throw new InvalidSubjectException("Improper " + fieldName + " entered: {}, please provide valid value");
        }

    }

    private void subjectFieldValidation(final String fieldName, final String fieldValue) throws InvalidSubjectException {
        subjectFieldValidation(fieldName, fieldValue, MAX_ALLOWABLE_LENGTH_64);

    }

    public void validateEmailEntries(final List<String> emailEntries) {

        for (final String emailAddress : emailEntries) {
            if (ValidationUtils.isNullOrEmpty(emailAddress)) {
                throw new IllegalArgumentException("Email can not be Null or Empty");
            }

            if (emailAddress.equals(OVERRIDING_OPERATOR)) {
                continue;
            }

            if (!ValidationUtils.validatePattern(EMAIL_REGEX, emailAddress)) {
                throw new IllegalArgumentException("Improper EmailId entered: " + emailAddress + ", provide valid EmailId");
            }
        }
    }

    private void validateCountryName(final String countryName) throws InvalidSubjectException {

        boolean isValidCountryName = false;

        if (ValidationUtils.validatePattern(COUNTRY_REGEX, countryName)) {
            final String countryCodeList[] = Locale.getISOCountries();
            isValidCountryName = (Arrays.binarySearch(countryCodeList, countryName.toUpperCase()) > 0);
        }

        if (!isValidCountryName) {
            throw new InvalidSubjectException("Select a valid Country name ex(IT, NZ, US)");
        }

    }

}
