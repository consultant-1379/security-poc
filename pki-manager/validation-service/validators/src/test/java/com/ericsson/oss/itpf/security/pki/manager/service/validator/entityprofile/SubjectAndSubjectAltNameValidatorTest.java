/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class SubjectAndSubjectAltNameValidatorTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(SubjectAndSubjectAltNameValidator.class);

    @InjectMocks
    SubjectAndSubjectAltNameValidator subjectAndSubjectAltNameValidator;

    @Mock
    EPSubjectValidator epSubjectValidator;

    @Mock
    EPSubjectAltNameValidator epSubjectAltNameValidator;

    private EntityProfile entityProfile = null;

    private EntityProfileSetUpData entityProfileSetUpToTest;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        entityProfileSetUpToTest = new EntityProfileSetUpData();
        entityProfile = entityProfileSetUpToTest.getEntityProfile();

    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidateSubjectAndSubjectAltName() {
        when(epSubjectValidator.validate(entityProfile)).thenReturn(Boolean.TRUE);
        when(epSubjectAltNameValidator.validate(entityProfile)).thenReturn(Boolean.TRUE);
        subjectAndSubjectAltNameValidator.validate(entityProfile);
        Mockito.verify(epSubjectValidator).validate(entityProfile);
        Mockito.verify(epSubjectAltNameValidator).validate(entityProfile);
    }

    /**
     * Method to test validate method in negative scenario.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateSubjectAndSubjectAltNameInNegative() {
        when(epSubjectValidator.validate(entityProfile)).thenReturn(Boolean.FALSE);
        when(epSubjectAltNameValidator.validate(entityProfile)).thenReturn(Boolean.FALSE);
        subjectAndSubjectAltNameValidator.validate(entityProfile);

    }

}
