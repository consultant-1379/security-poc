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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;

/**
 * This class creates default data for SubjectAltNameStringSetUpData objects
 */
public class SubjectAltNameStringSetUpData {

    private static final String SUBJECT_ALT_NAME_STRING_1 = "Directory1";
    private static final String OTHER_NAME_VALUE = "Other_arquillian";
    private static final String TYPE_ID = "12.600.12";

    /**
     * Method that returns valid SubjectAltNameString
     * 
     * @return SubjectAltNameString
     */
    public SubjectAltNameString getSubjectAltNameString(final String value) {
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(value);
        return subjectAltNameString;
    }

    /**
     * Method that returns valid SubjectAltNamevalues object
     * 
     * @return SubjectAltNameValues
     */
    public SubjectAltName getSANForCreate() {
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(SUBJECT_ALT_NAME_STRING_1);

        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        subjectAltNameValue.setValue(subjectAltNameString);

        final List<SubjectAltNameField> subjectAltNameValueList = new ArrayList<SubjectAltNameField>();
        subjectAltNameValueList.add(subjectAltNameValue);

        final SubjectAltName subjectAltName = new SubjectAltName();
        subjectAltName.setSubjectAltNameFields(subjectAltNameValueList);

        return subjectAltName;
    }

    /**
     * Method that returns different valid SubjectAltNamevalues object
     * 
     * @return SubjectAltNameValues
     */
    public SubjectAltName getSANForCreateNotEqual() {
        final OtherName otherName = new OtherName();
        otherName.setValue(OTHER_NAME_VALUE);
        otherName.setTypeId(TYPE_ID);

        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.OTHER_NAME);
        subjectAltNameValue.setValue(otherName);

        final List<SubjectAltNameField> subjectAltNameValueList = new ArrayList<SubjectAltNameField>();
        subjectAltNameValueList.add(subjectAltNameValue);
        final SubjectAltName subjectAltName = new SubjectAltName();
        subjectAltName.setSubjectAltNameFields(subjectAltNameValueList);
        return subjectAltName;
    }
}
