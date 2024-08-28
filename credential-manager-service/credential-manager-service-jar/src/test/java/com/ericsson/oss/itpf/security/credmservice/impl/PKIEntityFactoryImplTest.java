/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.junit.Before;
import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.api.PKIEntityFactory;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithmType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AbstractSubjectAltNameFieldValue;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.OtherName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

public class PKIEntityFactoryImplTest {

    PKIEntityFactory pkiEntityFactory;

    @Before
    public void setUp() {
        pkiEntityFactory = new PKIEntityFactoryImpl();
    }

    @Test
    public void testBuildForRequestByName() throws CredentialManagerServiceException {

        pkiEntityFactory.setName("entityName");
        final Entity entity = pkiEntityFactory.buildForRequest();

        assertNotNull(entity);
        assertEquals("entityName", entity.getEntityInfo().getName());
    }

    @Test
    public void testBuildForRequestById() throws CredentialManagerServiceException {

        pkiEntityFactory.setId(7777);
        final Entity entity = pkiEntityFactory.buildForRequest();

        assertNotNull(entity);
        assertEquals(7777, entity.getEntityInfo().getId());
    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testFailedValidateForRequest() throws CredentialManagerServiceException {

        pkiEntityFactory.setName("");
        pkiEntityFactory.buildForRequest();
    }

    @Test
    public void testBuildForCreate() throws CredentialManagerServiceException {

        pkiEntityFactory.setName("entityName");
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("entityName");
        pkiEntityFactory.setSubject(subject);
        pkiEntityFactory.setEntityProfileName("entityProfileName");
        final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setName("RSA");
        keyGenerationAlgorithm.setType(CredentialManagerAlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        pkiEntityFactory.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        final Entity entity = pkiEntityFactory.buildForCreate();

        assertNotNull(entity);
        assertEquals("entityName", entity.getEntityInfo().getName());
        for(SubjectField sf : entity.getEntityInfo().getSubject().getSubjectFields()) {
        	if(sf.getType()==SubjectFieldType.DN_QUALIFIER){
        		assertEquals("entityName", sf.getValue());
        	}
        }
        assertEquals("entityProfileName", entity.getEntityProfile().getName());
    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testFailedValidateForCreateForSubject() throws CredentialManagerServiceException {

        pkiEntityFactory.setName("entityName");
        pkiEntityFactory.setEntityProfileName("entityProfileName");
        pkiEntityFactory.buildForCreate();

    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testFailedValidateForCreateForName() throws CredentialManagerServiceException {

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("entityName");
        pkiEntityFactory.setSubject(subject);
        pkiEntityFactory.setEntityProfileName("entityProfileName");
        pkiEntityFactory.buildForCreate();
    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testFailedValidateForCreateForEntityProfileName() throws CredentialManagerServiceException {

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("entityName");
        pkiEntityFactory.setSubject(subject);
        pkiEntityFactory.buildForCreate();
    }

    @Test
    public void testBuildForUpdate() throws CredentialManagerServiceException {

        pkiEntityFactory.setId(7777);
        pkiEntityFactory.setName("entityName");
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("entityName");
        pkiEntityFactory.setSubject(subject);
        pkiEntityFactory.setEntityProfileName("entityProfileName");
        final CredentialManagerAlgorithm keyGenerationAlgorithm = new CredentialManagerAlgorithm();
        keyGenerationAlgorithm.setKeySize(2048);
        keyGenerationAlgorithm.setName("RSA");
        keyGenerationAlgorithm.setType(CredentialManagerAlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        pkiEntityFactory.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        final Entity entity = pkiEntityFactory.buildForUpdate();

        assertNotNull(entity);
        assertEquals(7777, entity.getEntityInfo().getId());
        assertEquals("entityName", entity.getEntityInfo().getName());
        for(SubjectField sf : entity.getEntityInfo().getSubject().getSubjectFields()) {
        	if(sf.getType()==SubjectFieldType.DN_QUALIFIER){
        		assertEquals("entityName", sf.getValue());
        	}
        }
        assertEquals("entityProfileName", entity.getEntityProfile().getName());
    }

    @Test(expected = CredentialManagerServiceException.class)
    public void testFailedValidateForUpdate() throws CredentialManagerServiceException {

        pkiEntityFactory.setName("entityName");
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        subject.setDnQualifier("entityName");
        pkiEntityFactory.setSubject(subject);
        pkiEntityFactory.setEntityProfileName("entityProfileName");
        pkiEntityFactory.buildForUpdate();
    }

    @Test
    public void testBuildForUpdateByEntity() throws CredentialManagerServiceException {

        final Entity pkiEntity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();
        final EntityProfile entityprofile = new EntityProfile();
        
        entityInfo.setId(7777);
        entityInfo.setName("entityName");
        
        pkiEntity.setEntityProfile(entityprofile);
        pkiEntity.getEntityProfile().setName("entityProfileName");

        final Subject subject = new Subject();
        final Map<SubjectFieldType, String> subjectMap = new HashMap<SubjectFieldType, String>();
        subjectMap.put(SubjectFieldType.DN_QUALIFIER, "entitySubject");

        for (Entry<SubjectFieldType, String> entry : subjectMap.entrySet()){
            SubjectField subFieldTemp = new SubjectField();
        	subFieldTemp.setType(entry.getKey());
        	subFieldTemp.setValue(entry.getValue());
        	subject.getSubjectFields().add(subFieldTemp);
        }
        
        final SubjectAltName subjectAltName = new SubjectAltName();
        final List<SubjectAltNameField> subjectAltNameFieldList = new ArrayList<SubjectAltNameField>();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.OTHER_NAME);
        final List<AbstractSubjectAltNameFieldValue> otherNames = new ArrayList<AbstractSubjectAltNameFieldValue>();
        final OtherName otherName = new OtherName();
        otherName.setTypeId("string");
        otherName.setValue("subjectAltName");
        otherNames.add(otherName);
        subjectAltNameField.setValue(otherName);
        subjectAltNameFieldList.add(subjectAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFieldList);

        entityInfo.setSubject(subject);
        entityInfo.setSubjectAltName(subjectAltName);
        pkiEntity.setEntityInfo(entityInfo);

        pkiEntityFactory.setEntity(pkiEntity);

        pkiEntityFactory.setEntityProfileName("entityProfileNameNew");
        final CredentialManagerSubject subjectNew = new CredentialManagerSubject();
        subjectNew.setDnQualifier("entitySubjectNew");
        pkiEntityFactory.setSubject(subjectNew);
        final Entity entity = pkiEntityFactory.buildForUpdate();

        assertNotNull(entity);
        assertEquals(7777, entity.getEntityInfo().getId());
        assertEquals("entityName", entity.getEntityInfo().getName());
        for(SubjectField sf : entity.getEntityInfo().getSubject().getSubjectFields()) {
        	if(sf.getType()==SubjectFieldType.DN_QUALIFIER){
        		assertEquals("entitySubjectNew", sf.getValue());
        	}
        }
        assertEquals("entityProfileNameNew", entity.getEntityProfile().getName());
        final OtherName otherNameNew = (OtherName) entity.getEntityInfo().getSubjectAltName().getSubjectAltNameFields().get(0).getValue();
        assertEquals("subjectAltName", otherNameNew.getValue());
    }
}
