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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.*;

public class SubjectSetUpData {

    private static final String COMMON_NAME = "CNarquillian";
    private static final String STREET_ADDRESS = "STarquillian";

    /**
     * Method that returns valid Subject object
     * 
     * @return Subject
     */
    public Subject getSubjectForCreate() {

        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

        final SubjectField common_name = new SubjectField();
        common_name.setType(SubjectFieldType.COMMON_NAME);
        common_name.setValue("CN=ERBS");

        final SubjectField organization = new SubjectField();
        organization.setType(SubjectFieldType.ORGANIZATION);
        organization.setValue("O=ENM");

        final SubjectField organization_unit = new SubjectField();
        organization_unit.setType(SubjectFieldType.ORGANIZATION_UNIT);
        organization_unit.setValue("OU=Ericsson");

        subjectFields.add(common_name);
        subjectFields.add(organization);
        subjectFields.add(organization);

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
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

        final SubjectField common_name = new SubjectField();
        common_name.setType(SubjectFieldType.COMMON_NAME);
        common_name.setValue(COMMON_NAME);

        final SubjectField street_address = new SubjectField();
        street_address.setType(SubjectFieldType.STREET_ADDRESS);
        street_address.setValue(STREET_ADDRESS);

        subjectFields.add(common_name);
        subjectFields.add(street_address);

        subject.setSubjectFields(subjectFields);

        return subject;
    }

}
