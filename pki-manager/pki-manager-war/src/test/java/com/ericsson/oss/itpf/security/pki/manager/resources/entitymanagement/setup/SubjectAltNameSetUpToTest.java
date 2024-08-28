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
package com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement.setup;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;

public class SubjectAltNameSetUpToTest {

    private static final String SUBJECT_ALT_NAME_STRING_1 = "Directory1";
    private SubjectAltName subjectAltName;

    /**
     * Method to provide dummy data for tests.
     */
    public SubjectAltNameSetUpToTest() {
        fillSubjectAltName();
    }

    /**
     * Method that returns SubjectAltName object for tests.
     */
    public SubjectAltName getSubjectAltName() {
        return subjectAltName;
    }

    private void fillSubjectAltName() {
        subjectAltName = createSubjectAltName();
    }

    private SubjectAltName createSubjectAltName() {
        final SubjectAltName subjectAltName = new SubjectAltName();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

        subjectAltNameField.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        subjectAltNameField.setValue(getSubjectAltNameString(SUBJECT_ALT_NAME_STRING_1));
        subjectAltNameFields.add(subjectAltNameField);

        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        return subjectAltName;
    }

    private AbstractSubjectAltNameFieldValue getSubjectAltNameString(final String value) {
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(value);

        return subjectAltNameString;
    }
}
