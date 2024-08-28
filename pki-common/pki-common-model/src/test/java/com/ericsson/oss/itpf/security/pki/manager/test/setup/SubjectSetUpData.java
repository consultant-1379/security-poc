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

import com.ericsson.oss.itpf.security.pki.common.model.*;

/**
 * This class acts as builder for {@link SubjectSetUpData}
 */
public class SubjectSetUpData {
    private static final String COMMON_NAME = "CNarquillian";
    private static final String DN_QUALIFIER = "DNarquillian";

    /**
     * Method that returns valid Subject object
     * 
     * @return Subject
     */
    public Subject getSubjectForCreate() {
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subjectField.setValue(COMMON_NAME);
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);

        return subject;
    }

    /**
     * Method that returns invalid Subject object
     * 
     * @return Subject
     */
    public Subject getSubjectForCreateNotEqual() {
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

        subjectField.setType(SubjectFieldType.DN_QUALIFIER);
        subjectField.setValue(DN_QUALIFIER);
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);

        return subject;
    }

    /**
     * Method that returns valid Subject object
     * 
     * @return Subject
     */
    public Subject getSubject(final String aSN1String) {

        return new Subject().fromASN1String(aSN1String);
    }
}
