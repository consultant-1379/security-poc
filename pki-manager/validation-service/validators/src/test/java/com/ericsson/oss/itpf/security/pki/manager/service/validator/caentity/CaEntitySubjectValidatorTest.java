/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2013
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.service.validator.caentity;

import static org.mockito.Mockito.when;

import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class CaEntitySubjectValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CaEntitySubjectValidator.class);

    @InjectMocks
    CaEntitySubjectValidator caEntitySubjValidator;

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

    private static final String OVERRIDING_OPERATOR = "?";
    private static final String INVALID_COMMON_NAME = "PK\"";

    CAEntity caEntity;

    CAEntityData caEntityData;

    EntityProfileData entityProfileData;

    SubjectAltName subjectAltName = new SubjectAltName();
    List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
    SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
    SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
    Map<String, Object> entityProfileMap = new HashMap<String, Object>();
    Map<String, Object> keyGenAlgorithmMap = new HashMap<String, Object>();

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        caEntity = entitiesSetUpData.getCaEntity();

        caEntityData = entitiesSetUpData.getCaEntityData();

        entityProfileData = caEntityData.getEntityProfileData();

        entityProfileMap.put("name", "ENMRootCAEntityProfile");
        entityProfileMap.put("active", Boolean.TRUE);

        keyGenAlgorithmMap.put(EntitiesSetUpData.NAME, "RSA");
        keyGenAlgorithmMap.put(EntitiesSetUpData.ALGORITHM_KEY_SIZE, 1024);
        keyGenAlgorithmMap.put(EntitiesSetUpData.ALGORITHM_TYPE, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);

        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY)).thenReturn(entitiesPersistenceHandler);

        when(entitiesPersistenceHandler.getEntityByName(entityProfileData.getName(), EntityProfileData.class, "name")).thenReturn(entityProfileData);

        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(entityProfileData);

    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testEmptySubject() {

        caEntity.getCertificateAuthority().getSubject().setSubjectFields(new ArrayList<SubjectField>());

        caEntitySubjValidator.validate(caEntity);

    }

    @Test(expected = InvalidSubjectException.class)
    public void testEmptySubjectValue() {

        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subjectField.setValue(null);
        subjectFields.add(subjectField);

        caEntity.getCertificateAuthority().getSubject().setSubjectFields(subjectFields);

        caEntitySubjValidator.validate(caEntity);

    }

    @Test(expected = InvalidSubjectException.class)
    public void testWrongSubject() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.DN_QUALIFIER);
        subjectField.setValue("ENM_Root");
        subjectFields.add(subjectField);

        final Subject subject = new Subject();

        subject.setSubjectFields(subjectFields);

        caEntity.getCertificateAuthority().setSubject(subject);

        caEntitySubjValidator.validate(caEntity);

    }

    @Test(expected = InvalidSubjectException.class)
    public void testWrongSubjectValue() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subjectField.setValue(OVERRIDING_OPERATOR);
        subjectFields.add(subjectField);

        final Subject subject = new Subject();

        subject.setSubjectFields(subjectFields);

        caEntity.getCertificateAuthority().setSubject(subject);

        caEntitySubjValidator.validate(caEntity);

    }

    @Test(expected = InvalidSubjectException.class)
    public void testSubjectInEntityProfileNull() {

        caEntityData.getEntityProfileData().setSubjectDN(null);

        caEntitySubjValidator.validate(caEntity);

    }

    @Test(expected = ProfileNotFoundException.class)
    public void testCreateEntityProfileNotFound() {

        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(null);

        caEntitySubjValidator.validate(caEntity);

    }

    @Test
    public void testvalidateEntitySubject() {

        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, "TestCA,TestCA1"));
        caEntity.getCertificateAuthority().getSubject().setSubjectFields(subjectFields);
        caEntitySubjValidator.validate(caEntity);

    }

    @Test(expected = InvalidSubjectException.class)
    public void testValidateCommaNotSupportedSubjectFieldType() {

        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.DC, "TestDC1,TestDC2"));
        caEntity.getCertificateAuthority().getSubject().setSubjectFields(subjectFields);
        caEntitySubjValidator.validate(caEntity);
    }

    private SubjectField getSubjectField(final SubjectFieldType subjectFieldType, final String subjectFieldValue) {

        final SubjectField subjectField = new SubjectField();
        subjectField.setType(subjectFieldType);
        subjectField.setValue(subjectFieldValue);

        return subjectField;

    }

    @Test(expected = InvalidSubjectException.class)
    public void testValidate_SubjectField_ThrowsInvalidSubjectException() {

        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subjectField.setValue(INVALID_COMMON_NAME);
        subjectFields.add(subjectField);

        caEntity.getCertificateAuthority().getSubject().setSubjectFields(subjectFields);

        caEntitySubjValidator.validate(caEntity);

    }
}
