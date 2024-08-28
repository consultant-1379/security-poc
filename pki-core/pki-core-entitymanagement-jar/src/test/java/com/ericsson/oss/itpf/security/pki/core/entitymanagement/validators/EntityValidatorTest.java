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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.validators;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.common.utils.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityInUseException;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class EntityValidatorTest {

    @Mock
    final private Logger logger = LoggerFactory.getLogger(EntityValidator.class);

    @InjectMocks
    EntityValidator entityValidator;

    @Mock
    EntityPersistenceHandler entityPersistenceHandler;

    @Mock
    SubjectValidator subjectValidator;

    @Mock
    SubjectAltNameValidator subjectAltNameValidator;

    SubjectAltName subjectAltName = new SubjectAltName();
    @Mock
    PersistenceManager persistenceManager;

    EntityInfo entityInfo = new EntityInfo();
    Subject subject = new Subject();
    EntityInfoData entityInfoData = new EntityInfoData();
    protected static final String OVERRIDING_OPERATOR = "?";
    private static final String LOGGER_VALIDATE_ENTITY = "Completed validating create Entity";

    @Before
    public void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        entityInfo = entitiesSetUpData.getEntityInfo();

        entityInfoData = entitiesSetUpData.getEntityInfoData();
    }

    @Test
    public void testValidateCreate() {

        entityValidator.validateEntity(entityInfo, OperationType.CREATE);

    }

    @Test
    public void testValidateUpdate() {

        when(persistenceManager.findEntity(EntityInfoData.class, entityInfo.getId())).thenReturn(entityInfoData);
        entityValidator.validateEntity(entityInfo, OperationType.UPDATE);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateNoEntity() {

        entityValidator.validateEntity(null, OperationType.CREATE);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateEntityNameNull() {
        entityInfo.setName(null);
        entityValidator.validateEntity(entityInfo, OperationType.CREATE);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateEmptyEntityName() {
        entityInfo.setName("");
        entityValidator.validateEntity(entityInfo, OperationType.CREATE);

    }

    @Test
    public void testValidateSAN() {
        SubjectField subjectField = new SubjectField();
        EntityInfo entityInfo_dummy = entityInfo;
        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subjectField.setValue("TCS");
        List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        entityInfo_dummy.setSubject(subject);
        entityInfo_dummy.setSubjectAltName(subjectAltName);
        entityValidator.validateEntity(entityInfo_dummy, OperationType.CREATE);
        // verify(subjectValidator, times(1)).validateSubjectValue(SubjectField.getType(), SubjectField.getValue());

    }

    @Test
    public void testIsSANValidWithEmptySubject() {

        entityInfo.setSubject(null);
        entityValidator.validateEntity(entityInfo, OperationType.CREATE);
        Mockito.verify(subjectAltNameValidator, Mockito.atLeastOnce()).validate((SubjectAltNameField) Mockito.any());
        Mockito.verify(logger).debug(LOGGER_VALIDATE_ENTITY);

    }

    @Test
    public void testIsSANValidWithEmptySubjectFieldType() {

        entityInfo.getSubject().getSubjectFields().get(0).setType(null);
        entityValidator.validateEntity(entityInfo, OperationType.CREATE);
        Mockito.verify(subjectAltNameValidator, Mockito.atLeastOnce()).validate((SubjectAltNameField) Mockito.any());
        Mockito.verify(logger).debug(LOGGER_VALIDATE_ENTITY);

    }

    @Test
    public void testSubjjectFieldValueEqualsToOverridingOperator() {

        entityInfo.getSubject().getSubjectFields().get(0).setValue(OVERRIDING_OPERATOR);
        entityValidator.validateEntity(entityInfo, OperationType.CREATE);
        Mockito.verify(subjectAltNameValidator, Mockito.atLeastOnce()).validate((SubjectAltNameField) Mockito.any());
        Mockito.verify(logger).debug(LOGGER_VALIDATE_ENTITY);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testIsSANValidWithEmptySubjectAndSAN() {

        entityInfo.setSubject(null);
        entityInfo.setSubjectAltName(null);
        entityValidator.validateEntity(entityInfo, OperationType.CREATE);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testIsSANValidWithEmptySubjectAndSANField() {

        entityInfo.setSubject(null);
        entityInfo.getSubjectAltName().getSubjectAltNameFields().set(0, null);
        entityValidator.validateEntity(entityInfo, OperationType.CREATE);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testIsSANValidWithEmptySubjectAndSANFieldType() {

        entityInfo.setSubject(null);
        entityInfo.getSubjectAltName().getSubjectAltNameFields().get(0).setType(null);
        entityValidator.validateEntity(entityInfo, OperationType.CREATE);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testIsSANValidWithEmptySubjectAndSANFieldValue() {

        entityInfo.setSubject(null);
        entityInfo.getSubjectAltName().getSubjectAltNameFields().get(0).setValue(null);
        entityValidator.validateEntity(entityInfo, OperationType.CREATE);

    }

    @Test
    public void testCheckEntityCanBeDeleted_EntityAlreadyDeletedException() {

        entityValidator.checkEntityCanBeDeleted(EntityStatus.DELETED);

    }

    @Test(expected = CoreEntityInUseException.class)
    public void testCheckEntityCanBeDeleted_EntityInUseException() {

        entityValidator.checkEntityCanBeDeleted(EntityStatus.ACTIVE);

    }

    @Test(expected = CoreEntityInUseException.class)
    public void testCheckEntityCanBeDeleted_EntityInUseExceptionByReissued() {

        entityValidator.checkEntityCanBeDeleted(EntityStatus.REISSUE);

    }

    @Test
    public void testCheckEntityCanBeDeleted() {

        assertTrue(entityValidator.checkEntityCanBeDeleted(EntityStatus.NEW));

    }
}
