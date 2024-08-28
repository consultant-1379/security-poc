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

import com.ericsson.oss.itpf.security.pki.common.model.*;

public class SubjectSetUpToTest {

    private static final String COMMON_NAME = "common_name";
    private static final String COUNTRY_NAME = "country_name";
    private Subject subject;

    /**
     * Method to provide dummy data for tests.
     */
    public SubjectSetUpToTest() {
        fillSubject();
    }

    /**
     * Method that returns Subject object for tests.
     */
    public Subject getSubject() {
        return subject;
    }

    private void fillSubject() {
        subject = createSubject();
    }

    private Subject createSubject() {
        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, COMMON_NAME));
        subjectFields.add(getSubjectField(SubjectFieldType.COUNTRY_NAME, COUNTRY_NAME));

        subject.setSubjectFields(subjectFields);

        return subject;
    }

    private SubjectField getSubjectField(final SubjectFieldType type, final String value) {
        final SubjectField subjectField = new SubjectField();

        subjectField.setType(type);
        subjectField.setValue(value);

        return subjectField;
    }
}
