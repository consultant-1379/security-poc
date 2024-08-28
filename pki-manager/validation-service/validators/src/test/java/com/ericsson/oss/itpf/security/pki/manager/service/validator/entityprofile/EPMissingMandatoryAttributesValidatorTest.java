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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class EPMissingMandatoryAttributesValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EPMissingMandatoryAttributesValidator.class);

    @InjectMocks
    EPMissingMandatoryAttributesValidator epMissingMandatoryAttributes;

    @Mock
    EPSubjectValidator entityProfileSubjectValidator;

    @Mock
    EPSubjectAltNameValidator entityProfileSubjectAltNameValidator;

    private EntityProfile entityProfile = null;
    private EntityProfileSetUpData entityProfileSetUpToTest;

    @Before
    public void setUp() throws Exception {
        entityProfileSetUpToTest = new EntityProfileSetUpData();
        entityProfile = entityProfileSetUpToTest.getEntityProfile();
    }

    /**
     * Method to test negative scenario
     */
    @Test
    public void testWithValidSubjectAndSubjectAltName() {
        epMissingMandatoryAttributes.validate(entityProfile);
    }

    /**
     * Method to test negative scenario
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testWithInValidSubject() {

        entityProfile.setSubject(null);
        epMissingMandatoryAttributes.validate(entityProfile);

    }

    /**
     * Method to test negative scenario
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testWithInValidSubjectAltName() {

        entityProfile.setSubject(null);
        entityProfile.getCertificateProfile().setForCAEntity(false);
        entityProfile.setSubjectAltNameExtension(null);
        epMissingMandatoryAttributes.validate(entityProfile);

    }

    /**
     * Method to test negative scenario
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testWithEmptySubjectFields() {

        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        entityProfile.getSubject().setSubjectFields(subjectFields);
        entityProfile.setSubjectAltNameExtension(null);
        epMissingMandatoryAttributes.validate(entityProfile);

    }

    /**
     * Method to test negative scenario
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testWithEmptySubjectAltNameFields() {

        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

        entityProfile.setSubject(null);
        entityProfile.getCertificateProfile().setForCAEntity(false);
        entityProfile.getSubjectAltNameExtension().setSubjectAltNameFields(subjectAltNameFields);

        epMissingMandatoryAttributes.validate(entityProfile);

    }
}
