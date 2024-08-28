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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.validators;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdkutils.util.CommonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.common.utils.ValidationUtils;

/**
 * This class validates all the fields namely IPAddress,RFC822Name, UniformResourceID,DirectoryName,RegisterID,EDIPartyName,OtherName,DNSName
 * 
 * present in Subject Alternate Name as per RFC standard
 * 
 * @author xchaagn
 * 
 */
public class SubjectAltNameValidator {
    @Inject
    private SubjectValidator subjectValidator;

    private static final int MAX_ALLOWABLE_LENGTH_255 = 255;
    private static final int MAX_ALLOWABLE_LENGTH_64 = 64;
    private static final int MAX_ALLOWABLE_LENGTH_200 = 200;


    private static final  String TYPE_ID_REGEX = "^[0-9.]{1,200}$";
    private static final  String OVERRIDING_OPERATOR = "?";

    private static final String UNIFORM_RESOURCE_ID_STRING = "UniformResourceID";
    private static final String DIRECTORY_NAME_STRING = "DirectoryName";
    private static final String NAME_ASSIGNER_STRING = "nameAssigner";
    private static final String PARTY_NAME_STRING = "partyName";
    private static final String OTHERNAME_TYPEID_STRING = "typeId";
    private static final String OTHERNAME_VALUE_STRING = "value";
    private static final String DNS_NAME_STRING = "dnsName";
    private static final String EMAIL_NAME_STRING = "email";
    private static final String IPADDRESS_NAME_STRING = "IPAddress";
    private static final String REGISTERID_NAME_STRING = "Register ID";

    /**
     * This method validates all the fields present in the Subject Alternate Name
     * 
     * @param SubjectAltNameValue
     * @param subjectAltNameField
     * @return Nothing
     */
    public void validate(final SubjectAltNameField subjectAltNameField) {
        final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue = subjectAltNameField.getValue();

        switch (subjectAltNameField.getType()) {
        case IP_ADDRESS:
            validateIPAddresses(subjectAltNameFieldValue);
            break;
        case RFC822_NAME:
            final List<String> emailEntries = convertSubjectAltNameValuesToString(subjectAltNameFieldValue, EMAIL_NAME_STRING);
            subjectValidator.validateEmailEntries(emailEntries);
            break;
        case UNIFORM_RESOURCE_IDENTIFIER:
            validateUniformResourceIds(subjectAltNameFieldValue);
            break;
        case DIRECTORY_NAME:
            validateDirNames(subjectAltNameFieldValue);
            break;
        case REGESTERED_ID:
            validateRegisterIds(subjectAltNameFieldValue);
            break;
        case EDI_PARTY_NAME:
            validateEdiPartyNames(subjectAltNameFieldValue);
            break;
        case OTHER_NAME:
            validateOtherNames(subjectAltNameFieldValue);
            break;
        case DNS_NAME:
            validateDnsNames(subjectAltNameFieldValue);
            break;
        default:
            throw new IllegalArgumentException("Unknown type mentioned in SubjectAtName " + subjectAltNameField.getType());
        }
    }

    private List<String> convertSubjectAltNameValuesToString(final AbstractSubjectAltNameFieldValue subjectAltNameValue, final String fieldName) {

        final List<String> sanStringValues = new ArrayList<>();
        if (subjectAltNameValue == null) {
            throw new IllegalArgumentException("subjectAltNameFieldValues for " + fieldName + " should not be empty or null");
        }

        sanStringValues.add(subjectAltNameValue.toString());

        return sanStringValues;
    }

    private List<EdiPartyName> convertSubjectAltNameToEDIPartyName(final AbstractSubjectAltNameFieldValue sanValue) {
        final List<EdiPartyName> ediPartyNames = new ArrayList<>();

        if (sanValue == null) {
            throw new IllegalArgumentException("subjectAltNameFieldValues for EDIPartyName should not be empty or null");
        }

        ediPartyNames.add((EdiPartyName) sanValue);

        return ediPartyNames;
    }

    private List<OtherName> convertSubjectAltNameToOtherName(final AbstractSubjectAltNameFieldValue sanValue) {
        final List<OtherName> otherNames = new ArrayList<>();
        if (sanValue == null) {
            throw new IllegalArgumentException("subjectAltNameFieldValues for OtherName should not be empty or null");
        }
        otherNames.add((OtherName) sanValue);

        return otherNames;
    }



    private void validateIPAddresses(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) {

        final List<String> ipAddresses = convertSubjectAltNameValuesToString(subjectAltNameFieldValue, IPADDRESS_NAME_STRING);

        for (final String ipAddress : ipAddresses) {
            if (ValidationUtils.isNullOrEmpty(ipAddress)) {
                throw new IllegalArgumentException("IpAddress can not be NULL or Empty");
            }

            if (ipAddress.equals(OVERRIDING_OPERATOR)) {
                continue;
            }

            if (!CommonUtil.isValidIpAddress(ipAddress)) {
                throw new IllegalArgumentException("Improper IPAddress : " + ipAddress + ", provide valid IPAddress");
            }
        }
    }

    private void validateUniformResourceIds(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) {
        final List<String> resourceIds = convertSubjectAltNameValuesToString(subjectAltNameFieldValue, UNIFORM_RESOURCE_ID_STRING);

        for (final String resourceId : resourceIds) {
            if (ValidationUtils.isNullOrEmpty(resourceId)) {
                throw new IllegalArgumentException("Resource ID ca not be Null or Empty");
            }

            subjectValidator.subjectFieldValidation(UNIFORM_RESOURCE_ID_STRING, resourceId, MAX_ALLOWABLE_LENGTH_255);
        }
    }

    private void validateDirNames(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) {
        final List<String> dirNames = convertSubjectAltNameValuesToString(subjectAltNameFieldValue, DIRECTORY_NAME_STRING);

        for (final String dir : dirNames) {
            if (ValidationUtils.isNullOrEmpty(dir)) {
                throw new IllegalArgumentException("DIRName can not be Null or Empty");
            }

            subjectValidator.subjectFieldValidation(DIRECTORY_NAME_STRING, dir, MAX_ALLOWABLE_LENGTH_64);
        }
    }

    private void validateRegisterIds(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) {
        final List<String> registerIds = convertSubjectAltNameValuesToString(subjectAltNameFieldValue, REGISTERID_NAME_STRING);

        for (final String registerId : registerIds) {
            if (ValidationUtils.isNullOrEmpty(registerId)) {
                throw new IllegalArgumentException("registerIds Should not be Empty or Null");
            }

            if (!isValidIdentifier(registerId)) {
                throw new IllegalArgumentException("Improper value provided, provide valid registerId details");
            }
        }
    }

    private boolean isValidIdentifier(final String identifier) {
        if (identifier.length() < 3 || identifier.charAt(1) != '.') {
            return false;
        }

        final char first = identifier.charAt(0);
        if (first < '0' || first > '2') {
            return false;
        }

        boolean periodAllowed = false;
        for (int i = identifier.length() - 1; i >= 2; i--) {
            final char ch = identifier.charAt(i);

            if ('0' <= ch && ch <= '9') {
                periodAllowed = true;
                continue;
            }

            if (ch == '.') {
                if (!periodAllowed) {
                    return false;
                }

                periodAllowed = false;
                continue;
            }

            return false;
        }

        return periodAllowed;
    }

    private void validateEdiPartyNames(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) throws IllegalArgumentException {

        final List<EdiPartyName> ediPartyNames = convertSubjectAltNameToEDIPartyName(subjectAltNameFieldValue);

        for (final EdiPartyName ediPartyName : ediPartyNames) {

            validateEdiPartyName(ediPartyName);
        }
    }

    private void validateEdiPartyName(final EdiPartyName ediPartyName) throws IllegalArgumentException {

        if (ediPartyName == null) {
            throw new IllegalArgumentException("Edipartyname values can not be null");
        }

        for (final Field ediFieldName : ediPartyName.getClass().getDeclaredFields()) {
            ediFieldName.setAccessible(true);

            try {
                if (ediFieldName.get(ediPartyName) == null) {
                    throw new IllegalArgumentException("Edipartyname should not be null");
                }
                if (ediFieldName.getName().matches(NAME_ASSIGNER_STRING) || ediFieldName.getName().matches(PARTY_NAME_STRING)) {
                    validateEdiPartyFieldValue(ediFieldName.getName(), (String) ediFieldName.get(ediPartyName));
                }

            } catch (final IllegalAccessException e) {
                throw new IllegalArgumentException("Occured in validating validatePartyName", e);
            }
        }
    }

    private void validateEdiPartyFieldValue(final String fieldName, final String fieldValue) throws IllegalArgumentException {

        if (ValidationUtils.isNullOrEmpty(fieldValue)) {
            throw new IllegalArgumentException(fieldName + " cannot be null or empty");
        }

        subjectValidator.subjectFieldValidation(fieldName, fieldValue, MAX_ALLOWABLE_LENGTH_64);
    }

    private void validateOtherNames(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) throws IllegalArgumentException {
        final List<OtherName> otherNames = convertSubjectAltNameToOtherName(subjectAltNameFieldValue);

        if (ValidationUtils.isNullOrEmpty(otherNames)) {
            throw new IllegalArgumentException("Othername should not be null or empty");
        }

        for (final OtherName otherName : otherNames) {
            validateOtherName(otherName);
        }
    }

    private void validateOtherName(final OtherName otherName) throws IllegalArgumentException {

        if (otherName == null) {
            throw new IllegalArgumentException("otherName values can not be null");
        }

        for (final Field otherNameField : otherName.getClass().getDeclaredFields()) {
            otherNameField.setAccessible(true);

            try {
                if (otherNameField.get(otherName) == null) {
                    throw new IllegalArgumentException("OtherName ::" + otherNameField.getName() + " is null");
                }

                if (otherNameField.getName().matches(OTHERNAME_TYPEID_STRING)) {
                    validateTypeID((String) otherNameField.get(otherName));
                } else if (otherNameField.getName().matches(OTHERNAME_VALUE_STRING)) {
                    validateOtherNameFieldValue(OTHERNAME_VALUE_STRING, (String) otherNameField.get(otherName));
                }
            } catch (final IllegalAccessException e) {
                throw new IllegalArgumentException("Occured in validating validateOtherName", e);
            }
        }
    }

    private void validateTypeID(final String typeIDValue) {
        if (!ValidationUtils.validatePattern(TYPE_ID_REGEX, typeIDValue)) {
            throw new IllegalArgumentException("Improper typeIDValue : " + typeIDValue + ", provide valid typeIDValue");
        }
    }

    private void validateOtherNameFieldValue(final String fieldName, final String fieldValue) {
        if (ValidationUtils.isNullOrEmpty(fieldValue)) {
            throw new IllegalArgumentException(fieldName + " cannot be null or empty");
        }

        subjectValidator.subjectFieldValidation(fieldName, fieldValue, MAX_ALLOWABLE_LENGTH_200);
    }

    private void validateDnsNames(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) {
        final List<String> dnsNamelist = convertSubjectAltNameValuesToString(subjectAltNameFieldValue, DNS_NAME_STRING);

        if (ValidationUtils.isNullOrEmpty(dnsNamelist)) {
            throw new IllegalArgumentException("DNSName should not be empty or null ");
        }

        for (final String dnsName : dnsNamelist) {

            if (ValidationUtils.isNullOrEmpty(dnsName)) {
                throw new IllegalArgumentException("DNS Name should not be Empty or Null");
            }

            subjectValidator.subjectFieldValidation(DNS_NAME_STRING, dnsName, MAX_ALLOWABLE_LENGTH_255);
        }
    }
}
