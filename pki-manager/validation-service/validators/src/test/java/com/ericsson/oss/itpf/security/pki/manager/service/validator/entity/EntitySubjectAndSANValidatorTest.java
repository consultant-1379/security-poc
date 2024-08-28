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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entity;

import static org.mockito.Mockito.when;

import java.util.*;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.*;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class EntitySubjectAndSANValidatorTest {

    @Spy
    final private Logger logger = LoggerFactory.getLogger(EntitySubjectAndSANValidator.class);

    @InjectMocks
    EntitySubjectAndSANValidator entitySubjAndSANValidator;

    @Mock
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Mock
    EntitiesPersistenceHandler entitiesPersistenceHandler;

    @Mock
    SubjectValidator subjectValidator;

    @Mock
    SubjectAltNameValidator subjectAltNameValidator;

    @Mock
    PersistenceManager persistenceManager;

    Entity entity;

    EntityData entityData;

    EntityProfileData entityProfileData;
    Map<String, Object> entityProfileMap = new HashMap<String, Object>();

    private String[] unsupportedSubjectChars = {"\\","/","=","\""};

    private static final String INVALID_COUNTRY_NAME = ".*";

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public <T extends AbstractSubjectAltNameFieldValue> void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        entity = entitiesSetUpData.getEntity();

        entityData = entitiesSetUpData.getEntityData();

        entityProfileData = entityData.getEntityProfileData();

        entityProfileMap.put("name", "ENMRootCAEntityProfile");
        entityProfileMap.put("active", Boolean.TRUE);

        entityProfileData.getCertificateProfileData().setForCAEntity(false);

        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(entityProfileData);
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entitiesPersistenceHandler);
        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(entityProfileData);
        when(entitiesPersistenceHandler.getEntityByName(entityProfileData.getName(), EntityProfileData.class, "name")).thenReturn(entityProfileData);
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entity.getCategory().getName(), "name")).thenReturn(entityData.getEntityCategoryData());
    }

    /**
     * Method to test validate method in negative scenario.When providing empty Subject fields.
     */
    @Test
    public void testEmptySubject() {

        entity.getEntityInfo().getSubject().setSubjectFields(new ArrayList<SubjectField>());

        entitySubjAndSANValidator.validate(entity);

    }

    /**
     * Method to test validate method in negative scenario.When providing SubjectAltName fields.
     */
    @Test
    public void testEmptySAN() {

        entity.getEntityInfo().getSubjectAltName().setSubjectAltNameFields(new ArrayList<SubjectAltNameField>());

        entitySubjAndSANValidator.validate(entity);

    }

    /**
     * Method to test validate method in positive scenario.When Empty SubjectValues.
     */
    @Test
    public void testEmptySubjectValue() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subjectField.setValue(null);
        subjectFields.add(subjectField);

        entity.getEntityInfo().getSubject().setSubjectFields(subjectFields);

        entitySubjAndSANValidator.validate(entity);

    }

    /**
     * Method to test validate method in negative scenario.When wrong Subject is provided.
     */
    @Test(expected = InvalidSubjectException.class)
    public void testWrongSubject() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.DN_QUALIFIER);
        subjectField.setValue("ENM_Root");
        subjectFields.add(subjectField);

        final Subject subject = new Subject();

        subject.setSubjectFields(subjectFields);
        entity.getEntityInfo().setSubject(subject);

        entitySubjAndSANValidator.validate(entity);

    }

    /**
     * Method to test unsupported chars in the Subject is provided.
     */
    @Test
    public void testInvalidCharsSubject() {
        int exceptionCounter = 0;
        //Subject field contains unsupported characters \=/"
        for (int i = 0; i < unsupportedSubjectChars.length; i++) {

            final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
            final SubjectField subjectField = new SubjectField();
            subjectField.setType(SubjectFieldType.DN_QUALIFIER);
            subjectField.setValue("ENM" + unsupportedSubjectChars[i] + "_Root");
            subjectFields.add(subjectField);

            final Subject subject = new Subject();

            subject.setSubjectFields(subjectFields);
            entity.getEntityInfo().setSubject(subject);
            try {
                entitySubjAndSANValidator.validate(entity);
            } catch (InvalidSubjectException e) {
                if (e.getMessage().equals(ErrorMessages.UNSUPPORTED_CHARACTERS_FOR_DIRECTORY_STRING_SUBJECT)) {
                    exceptionCounter++;
                }
            }
        }
        Assert.assertTrue(exceptionCounter==unsupportedSubjectChars.length);
    }

    @Test
    public void testCommaSupportedRDNSubject() {
        boolean result=false;
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subjectField.setValue("ENM_Root\\,Ericsson");
        subjectFields.add(subjectField);
        final Subject subject = new Subject();

        subject.setSubjectFields(subjectFields);
        entity.getEntityInfo().setSubject(subject);
        try {
            entitySubjAndSANValidator.validate(entity);
        } catch (InvalidSubjectException e) {
            if (e.getMessage().equals(ErrorMessages.UNSUPPORTED_CHARACTERS_FOR_DIRECTORY_STRING_SUBJECT)) {
                result = true;
            }
        }
        Assert.assertTrue(result);
    }

    @Test
    public void testCommaNotSupportedRDNSubject() {
        boolean result=false;
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.DC);
        subjectField.setValue("ENM_Root,Ericsson");
        subjectFields.add(subjectField);
        final Subject subject = new Subject();

        subject.setSubjectFields(subjectFields);
        entity.getEntityInfo().setSubject(subject);
        try {
            entitySubjAndSANValidator.validate(entity);
        } catch (InvalidSubjectException e) {
            if (e.getMessage().equals(ErrorMessages.UNSUPPORTED_CHARACTERS_SUBJECT)) {
                result = true;
            }
        }
        Assert.assertTrue(result);
    }

    @Test(expected = InvalidSubjectException.class)
    public void testValidate_SubjectField_UnSupprotedChars_ThrowsInvalidSubjectException() {

        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COUNTRY_NAME);
        subjectField.setValue(INVALID_COUNTRY_NAME);
        subjectFields.add(subjectField);

        final Subject subject = new Subject();

        subject.setSubjectFields(subjectFields);
        entity.getEntityInfo().setSubject(subject);

        entitySubjAndSANValidator.validate(entity);

    }

}
