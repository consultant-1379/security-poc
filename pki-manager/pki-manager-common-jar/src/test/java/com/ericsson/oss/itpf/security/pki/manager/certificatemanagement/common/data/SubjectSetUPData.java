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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.*;

public class SubjectSetUPData {

    /**
     * Method to generate Subject.
     * 
     * @return Subject.
     */
    public Subject getSubject() {
        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subject.setSubjectFields(subjectFields);
        return subject;
    }

    /**
     * Method to generate Subject using commonName.
     * 
     * @param commonName
     *            commonName to generate Subject.
     * @return Subject.
     */

    public Subject getSubject(final String commonName) {

        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

        final SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subjectField.setValue(commonName);
        subjectFields.add(subjectField);

        subject.setSubjectFields(subjectFields);
        return subject;
    }

    /**
     * Method to generate Subject using organizationUnit and organization.
     * 
     * @param organizationUnit
     *            organizationUnit to generate Subject.
     * @param organization
     *            organization to generate Subject.
     * 
     * @return Subject.
     */
    public Subject getSubject(final String organization, final String organizationUnit) {

        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

        final SubjectField subjectField_organization = new SubjectField();
        subjectField_organization.setType(SubjectFieldType.ORGANIZATION);
        subjectField_organization.setValue(organization);
        subjectFields.add(subjectField_organization);

        final SubjectField subjectField_organizationUnit = new SubjectField();
        subjectField_organizationUnit.setType(SubjectFieldType.ORGANIZATION_UNIT);
        subjectField_organizationUnit.setValue(organizationUnit);
        subjectFields.add(subjectField_organizationUnit);

        subject.setSubjectFields(subjectFields);
        return subject;
    }

    /**
     * Method to generate Subject using organizationUnit,organization and commonName.
     * 
     * @param commonName
     *            commonName to generate Subject.
     * @param organizationUnit
     *            organizationUnit to generate Subject.
     * @param organization
     *            organization to generate Subject.
     * 
     * @return Subject.
     */
    public Subject getSubject(final String commonName, final String organizationUnit, final String organization) {

        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

        final SubjectField subjectField_commonName = new SubjectField();
        subjectField_commonName.setType(SubjectFieldType.COMMON_NAME);
        subjectField_commonName.setValue(commonName);
        subjectFields.add(subjectField_commonName);

        final SubjectField subjectField_organizationUnit = new SubjectField();
        subjectField_organizationUnit.setType(SubjectFieldType.ORGANIZATION_UNIT);
        subjectField_organizationUnit.setValue(organizationUnit);
        subjectFields.add(subjectField_organizationUnit);

        final SubjectField subjectField_organization = new SubjectField();
        subjectField_organization.setType(SubjectFieldType.ORGANIZATION);
        subjectField_organization.setValue(organization);
        subjectFields.add(subjectField_organization);

        subject.setSubjectFields(subjectFields);
        return subject;
    }
}
