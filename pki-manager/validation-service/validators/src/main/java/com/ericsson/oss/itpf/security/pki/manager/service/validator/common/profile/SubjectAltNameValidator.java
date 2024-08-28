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

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdkutils.util.CommonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AbstractSubjectAltNameFieldValue;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.EdiPartyName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.OtherName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;

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

    private final static int MAX_ALLOWABLE_LENGTH_255 = 255;
    private final static int MAX_ALLOWABLE_LENGTH_64 = 64;
    private final static int MAX_ALLOWABLE_LENGTH_200 = 200;


    private final static String TYPE_ID_REGEX = "^[0-9.]{1,200}$";
    private static final String OVERRIDING_OPERATOR = "?";
    
    private static final String DNS_NAME_REGEX = "^(?=.{1,255}$)(?!.*\\.{2})(((?:(?!-)[\\x21-\\x7E]{1,63}(?<!-|_)(?:\\.|$)){1,})*)(?<!\\.)$";
    private static final String DIRECTORY_NAME_REGEX = "^([a-z][a-z0-9-]*)=(?![ #])(((?![\\=+,;<>]).)|(\\[ \\#=+,;<>])|(\\[a-f0-9][a-f0-9]))*(,([a-z][a-z0-9-]*)=(?![ #])(((?![\\=+,;<>]).)|(\\[ \\#=+,;<>])|(\\[a-f0-9][a-f0-9]))*)*$";
    private static final String URI_REGEX = "[A-Za-z][A-Za-z0-9+\\-.]*:(?://(?:(?:[A-Za-z0-9\\-._~!$&'()*+,;=:]|%[0-9A-Fa-f]{2})*@)?(?:\\[(?:(?:(?:(?:[0-9A-Fa-f]{1,4}:){6}|::(?:[0-9A-Fa-f]{1,4}:){5}|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}|(?:(?:[0-9A-Fa-f]{1,4}:){0,1}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}|(?:(?:[0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}|(?:(?:[0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:|(?:(?:[0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})?::)(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})?::)|[Vv][0-9A-Fa-f]+\\.[A-Za-z0-9\\-._~!$&'()*+,;=:]+)\\]|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[A-Za-z0-9\\-._~!$&'()*+,;=]|%[0-9A-Fa-f]{2})*)(?::[0-9]*)?(?:/(?:[A-Za-z0-9\\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*)*|/(?:(?:[A-Za-z0-9\\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})+(?:/(?:[A-Za-z0-9\\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*)*)?|(?:[A-Za-z0-9\\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})+(?:/(?:[A-Za-z0-9\\-._~!$&'()*+,;=:@]|%[0-9A-Fa-f]{2})*)*|)(?:\\?(?:[A-Za-z0-9\\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*)?(?:\\#(?:[A-Za-z0-9\\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})*)?";
    private static final String DIGIT_ONLY_REGEX = "^(?=^.{1,255}$)(([0-9]{1,63}(?:\\.|$)){1,})(?!\\.)$";
    
    private final static String UNIFORM_RESOURCE_ID_STRING = "UniformResourceID";
    private final static String DIRECTORY_NAME_STRING = "DirectoryName";
    private final static String NAME_ASSIGNER_STRING = "nameAssigner";
    private final static String PARTY_NAME_STRING = "partyName";
    private final static String OTHERNAME_TYPEID_STRING = "typeId";
    private final static String OTHERNAME_VALUE_STRING = "value";
    private final static String DNS_NAME_STRING = "dnsName";
    private final static String EMAIL_NAME_STRING = "email";
    private final static String IPADDRESS_NAME_STRING = "IPAddress";
    private final static String REGISTERID_NAME_STRING = "Register ID";

    /**
     * This method validates all the fields present in the Subject Alternate Name
     * 
     * @param SubjectAltNameValue
     * @param subjectAltNameField
     * @return Nothing
     * 
     * @throws InvalidSubjectAltNameExtension
     *             thrown when given subject alt name is not valid.
     */
    public void validate(final SubjectAltNameField subjectAltNameField) throws InvalidSubjectAltNameExtension {
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
            throw new InvalidSubjectAltNameExtension("Unknown type mentioned in SubjectAltName " + subjectAltNameField.getType());
        }
    }

    private List<String> convertSubjectAltNameValuesToString(final AbstractSubjectAltNameFieldValue subjectAltNameValue, final String fieldName) throws InvalidSubjectAltNameExtension {

        final List<String> sanStringValues = new ArrayList<String>();
        if (subjectAltNameValue == null) {
            throw new InvalidSubjectAltNameExtension("subjectAltNameFieldValues for " + fieldName + " cannot be Null or Empty");
        }

        sanStringValues.add(subjectAltNameValue.toString());

        return sanStringValues;
    }

    private List<EdiPartyName> convertSubjectAltNameToEDIPartyName(final AbstractSubjectAltNameFieldValue sanValue) throws InvalidSubjectAltNameExtension {
        final List<EdiPartyName> ediPartyNames = new ArrayList<EdiPartyName>();

        if (sanValue == null) {
            throw new InvalidSubjectAltNameExtension("subjectAltNameFieldValues for EDIPartyName cannot be Null or Empty");
        }

        ediPartyNames.add((EdiPartyName) sanValue);
        return ediPartyNames;
    }

    private List<OtherName> convertSubjectAltNameToOtherName(final AbstractSubjectAltNameFieldValue sanValue) throws InvalidSubjectAltNameExtension {
        final List<OtherName> otherNames = new ArrayList<OtherName>();
        if (sanValue == null) {
            throw new InvalidSubjectAltNameExtension("subjectAltNameFieldValues for OtherName cannot be Null or Empty");
        }
        otherNames.add((OtherName) sanValue);
        return otherNames;
    }

    private void validateIPAddresses(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) throws InvalidSubjectAltNameExtension {

        final List<String> ipAddresses = convertSubjectAltNameValuesToString(subjectAltNameFieldValue, IPADDRESS_NAME_STRING);

        for (final String ipAddress : ipAddresses) {
            if (ValidationUtils.isNullOrEmpty(ipAddress)) {
                throw new InvalidSubjectAltNameExtension("IpAddress cannot be Null or Empty");
            }

            if (ipAddress.equals(OVERRIDING_OPERATOR)) {
                continue;
            }

            if (!CommonUtil.isValidIpAddress(ipAddress)) {
                throw new InvalidSubjectAltNameExtension("Improper IPAddress : " + ipAddress + ", provide valid IPAddress");
            }
        }
    }

    private void validateUniformResourceIds(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) throws InvalidSubjectAltNameExtension {
        final List<String> resourceIds = convertSubjectAltNameValuesToString(subjectAltNameFieldValue, UNIFORM_RESOURCE_ID_STRING);

        for (final String resourceId : resourceIds) {
            if (ValidationUtils.isNullOrEmpty(resourceId)) {
                throw new InvalidSubjectAltNameExtension("Resource ID cannot be Null or Empty");
            }
            
            if (resourceId.equals(OVERRIDING_OPERATOR)) {
                continue;
            }
            if(!ValidationUtils.validatePattern(URI_REGEX, resourceId)){
            	throw new InvalidSubjectAltNameExtension("ResourceIDs should be of the form URL,URI or URN");
            }

            subjectValidator.subjectFieldValidation(UNIFORM_RESOURCE_ID_STRING, resourceId, MAX_ALLOWABLE_LENGTH_255);
        }
    }

    private void validateDirNames(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) throws InvalidSubjectAltNameExtension {
        final List<String> dirNames = convertSubjectAltNameValuesToString(subjectAltNameFieldValue, DIRECTORY_NAME_STRING);

        for (final String dir : dirNames) {
            if (ValidationUtils.isNullOrEmpty(dir)) {
                throw new InvalidSubjectAltNameExtension("DIRName cannot be Null or Empty");
            }
            if (dir.equals(OVERRIDING_OPERATOR)) {
                continue;
            }
            if(!ValidationUtils.validatePattern(DIRECTORY_NAME_REGEX, dir)){
            	throw new InvalidSubjectAltNameExtension("DirectoryName should be of the form DistinguishedName");
            }
            
            subjectValidator.subjectFieldValidation(DIRECTORY_NAME_STRING, dir, MAX_ALLOWABLE_LENGTH_64);
        }
    }

    private void validateRegisterIds(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) throws InvalidSubjectAltNameExtension {
        final List<String> registerIds = convertSubjectAltNameValuesToString(subjectAltNameFieldValue, REGISTERID_NAME_STRING);

        for (final String registerId : registerIds) {
            if (ValidationUtils.isNullOrEmpty(registerId)) {
                throw new InvalidSubjectAltNameExtension("registerIds cannot be Null or Empty");
            }
            if (registerId.equals(OVERRIDING_OPERATOR)) {
                continue;
            }
            if (!isValidIdentifier(registerId)) {
                throw new InvalidSubjectAltNameExtension("Improper value provided, provide valid registerId details");
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

    private void validateEdiPartyNames(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) throws InvalidSubjectAltNameExtension {

        final List<EdiPartyName> ediPartyNames = convertSubjectAltNameToEDIPartyName(subjectAltNameFieldValue);

        for (final EdiPartyName ediPartyName : ediPartyNames) {
            
            validateEdiPartyName(ediPartyName);
        }
    }

    private void validateEdiPartyName(final EdiPartyName ediPartyName) throws InvalidSubjectAltNameExtension {

        if (ediPartyName == null) {
            throw new InvalidSubjectAltNameExtension("Edipartyname values cannot be Null or Empty");
        }

        for (final Field ediFieldName : ediPartyName.getClass().getDeclaredFields()) {
            ediFieldName.setAccessible(true);

            try {
                if (ediFieldName.get(ediPartyName) == null) {
                    throw new InvalidSubjectAltNameExtension("Edipartyname cannot be Null or Empty");
                }
                if (ediFieldName.getName().matches(NAME_ASSIGNER_STRING) || ediFieldName.getName().matches(PARTY_NAME_STRING)) {
                    validateEdiPartyFieldValue(ediFieldName.getName(), (String) ediFieldName.get(ediPartyName));
                }

            } catch (final IllegalAccessException e) {
                throw new InvalidSubjectAltNameExtension("Occured in validating validatePartyName", e);
            }
        }
    }

    private void validateEdiPartyFieldValue(final String fieldName, final String fieldValue) throws InvalidSubjectAltNameExtension {

        if (ValidationUtils.isNullOrEmpty(fieldValue)) {
            throw new InvalidSubjectAltNameExtension(fieldName + " cannot be Null or Empty");
        }

        subjectValidator.subjectFieldValidation(fieldName, fieldValue, MAX_ALLOWABLE_LENGTH_64);
    }

    private void validateOtherNames(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) throws InvalidSubjectAltNameExtension {
        final List<OtherName> otherNames = convertSubjectAltNameToOtherName(subjectAltNameFieldValue);

        if (ValidationUtils.isNullOrEmpty(otherNames)) {
            throw new InvalidSubjectAltNameExtension("Othername cannot be Null or Empty");
        }

        for (final OtherName otherName : otherNames) {
            validateOtherName(otherName);
        }
    }

    private void validateOtherName(final OtherName otherName) throws InvalidSubjectAltNameExtension {

        if (otherName == null) {
            throw new InvalidSubjectAltNameExtension("otherName values cannot be Null or Empty");
        }

        for (final Field otherNameField : otherName.getClass().getDeclaredFields()) {
            otherNameField.setAccessible(true);

            try {
                if (otherNameField.get(otherName) == null) {
                    throw new InvalidSubjectAltNameExtension("OtherName " + otherNameField.getName() + " is null");
                }

                if (otherNameField.getName().matches(OTHERNAME_TYPEID_STRING)) {
                    validateTypeID((String) otherNameField.get(otherName));
                } else if (otherNameField.getName().matches(OTHERNAME_VALUE_STRING)) {
                    validateOtherNameFieldValue(OTHERNAME_VALUE_STRING, (String) otherNameField.get(otherName));
                }
            } catch (final IllegalAccessException e) {
                throw new InvalidSubjectAltNameExtension("Occured in validating validateOtherName", e);
            }
        }
    }

    private void validateTypeID(final String typeIDValue) throws InvalidSubjectAltNameExtension {
        if (typeIDValue.equals(OVERRIDING_OPERATOR)) {
            return;
        }        
        if (!ValidationUtils.validatePattern(TYPE_ID_REGEX, typeIDValue)) {
            throw new InvalidSubjectAltNameExtension("Improper typeIDValue : " + typeIDValue + ", provide valid typeIDValue");
        }
    }

    private void validateOtherNameFieldValue(final String fieldName, final String fieldValue) throws InvalidSubjectAltNameExtension {
        if (ValidationUtils.isNullOrEmpty(fieldValue)) {
            throw new InvalidSubjectAltNameExtension(fieldName + " cannot be Null or Empty");
        }
        if (fieldValue.equals(OVERRIDING_OPERATOR)) {
            return;
        }
        subjectValidator.subjectFieldValidation(fieldName, fieldValue, MAX_ALLOWABLE_LENGTH_200);
    }

    private void validateDnsNames(final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue) throws InvalidSubjectAltNameExtension {
        final List<String> dnsNamelist = convertSubjectAltNameValuesToString(subjectAltNameFieldValue, DNS_NAME_STRING);

        if (ValidationUtils.isNullOrEmpty(dnsNamelist)) {
            throw new InvalidSubjectAltNameExtension("DNSName cannot be Null or Empty ");
        }
        

        for (final String dnsName : dnsNamelist) {

            if (ValidationUtils.isNullOrEmpty(dnsName)) {
                throw new InvalidSubjectAltNameExtension("DNS Name cannot be Null or Empty");
            }
            if (dnsName.equals(OVERRIDING_OPERATOR)) {
                continue;
            }
            if (!(ValidationUtils.validatePattern(DNS_NAME_REGEX, dnsName) && !ValidationUtils.validatePattern(DIGIT_ONLY_REGEX, dnsName))) {
            	throw new InvalidSubjectAltNameExtension("DNS should be of the form URI");
            }

            subjectValidator.subjectFieldValidation(DNS_NAME_STRING, dnsName, MAX_ALLOWABLE_LENGTH_255);
        }
    }
}
