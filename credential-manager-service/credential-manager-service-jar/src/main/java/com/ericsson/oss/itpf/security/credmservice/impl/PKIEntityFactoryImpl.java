/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.impl;

import java.io.File;

import com.ericsson.oss.itpf.security.credmservice.api.PKIEntityFactory;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerCategoriesException;
import com.ericsson.oss.itpf.security.credmservice.util.AppCategoryXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

public class PKIEntityFactoryImpl implements PKIEntityFactory {

    private Long id;
    private String name;

    private CredentialManagerSubject subject;
    private CredentialManagerSubjectAltName subjectAltName;
    private CredentialManagerAlgorithm keyGenerationAlgorithm;
    private String entityProfileName;

    private Entity pkiEntity;

    @Override
    public Entity buildForRequest() throws CredentialManagerInvalidEntityException {
        final Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();
        validateForRequest();
        if (id != null) {
            entityInfo.setId(id);
        }
        if (name != null) {
            entityInfo.setName(name);
        }
        entity.setEntityInfo(entityInfo);
        return entity;
    }

    @Override
    public Entity buildForCreate() throws CredentialManagerInvalidEntityException {
        final Entity entity = new Entity();
        final EntityProfile entityprofile = new EntityProfile();
        final EntityCategory entitycategory = new EntityCategory();
        validateForCreate();

        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(name);
        entityInfo.setSubject(PKIModelMapper.pkiSubjectFrom(subject));
        if (subjectAltName != null) {
            entityInfo.setSubjectAltName(PKIModelMapper.pkiSubjectAltNameFrom(subjectAltName));
        }

        entitycategory.setName(CategoryManagement.getServiceName());
        entity.setCategory(entitycategory);// PKI sets the id and isModifiable (false on default)
        entity.setEntityInfo(entityInfo);
        entity.setKeyGenerationAlgorithm(PKIModelMapper.pkiAlgorithmFrom(keyGenerationAlgorithm));
        entity.setEntityProfile(entityprofile);
        entity.getEntityProfile().setName(entityProfileName);

        return entity;
    }

    @Override
    public Entity buildForUpdate() throws CredentialManagerInvalidEntityException {
        Entity entity;
        if (pkiEntity != null) {
            entity = pkiEntity;
        } else {
            entity = new Entity();
        }

        validateForUpdate();

        EntityInfo entityInfo = entity.getEntityInfo();
        if (entityInfo == null) {
            entityInfo = new EntityInfo();
        }

        if (idIsValid()) {
            entityInfo.setId(id);
        }
        if (nameIsValid()) {
            entityInfo.setName(name);
        }

        entity.setKeyGenerationAlgorithm(PKIModelMapper.pkiAlgorithmFrom(keyGenerationAlgorithm));
        Subject subj = entityInfo.getSubject();
        SubjectAltName subjAltName = entityInfo.getSubjectAltName();

        if (subj == null) {
            subj = new Subject();
        }

        if (subjAltName == null) {
            subjAltName = new SubjectAltName();
        }

        if (subjectIsValid()) {
            entityInfo.setSubject(PKIModelMapper.pkiSubjectFrom(subject));
        }

        if (subjectAltName != null) {
            entityInfo.setSubjectAltName(PKIModelMapper.pkiSubjectAltNameFrom(subjectAltName));
        }

        if (entity.getCategory() == null) {
            final EntityCategory category = new EntityCategory();
            final File xmlRootPath = new File(PropertiesReader.getConfigProperties().getProperty("path.xml.pki.configuration"));
            final File xmlCategoryPath = new File(xmlRootPath.getParent() + "/PKICategories.xml");
            AppCategoryXmlConfiguration categoryObj = null;
            try {
                categoryObj = new AppCategoryXmlConfiguration(xmlCategoryPath);
            } catch (final CredentialManagerCategoriesException e) { // NOSONAR
                throw new CredentialManagerInvalidEntityException("Error parsing xml category file in path: " + xmlCategoryPath.toString());
            }
            category.setName(categoryObj.getServiceCategory());
            entity.setCategory(category);
        }

        entity.setEntityInfo(entityInfo);
        if (entityProfileNamesIsValid()) {
            if (entity.getEntityProfile() == null) {
                final EntityProfile entityprofile = new EntityProfile();
                entity.setEntityProfile(entityprofile);
            }
            entity.getEntityProfile().setName(entityProfileName);
        }

        return entity;
    }

    @Override
    public PKIEntityFactory setId(final long id) {
        this.id = id;
        return this;
    }

    @Override
    public PKIEntityFactory setName(final String name) {
        this.name = name;
        return this;
    }

    @Override
    public PKIEntityFactory setSubject(final CredentialManagerSubject subject) {
        this.subject = subject;
        return this;
    }

    @Override
    public PKIEntityFactory setSubjectAltName(final CredentialManagerSubjectAltName subjectAltName) {

        this.subjectAltName = subjectAltName;
        return this;
    }

    @Override
    public PKIEntityFactory setKeyGenerationAlgorithm(final CredentialManagerAlgorithm keyGenerationAlgorithm) {
        this.keyGenerationAlgorithm = keyGenerationAlgorithm;
        return this;
    }

    @Override
    public PKIEntityFactory setEntityProfileName(final String entityProfileName) {
        this.entityProfileName = entityProfileName;
        return this;
    }

    @Override
    public PKIEntityFactory setEntity(final Entity pkiEntity) {
        this.pkiEntity = pkiEntity;
        return this;
    }

    private void validateForRequest() throws CredentialManagerInvalidEntityException {
        if (!idIsValid() && !nameIsValid() || idIsValid() && nameIsValid()) {
            throw new CredentialManagerInvalidEntityException("Id and Name are empty or both fitted");
        }
    }

    private void validateForCreate() throws CredentialManagerInvalidEntityException {
        if (!nameIsValid() || !subjectIsValid() || !entityProfileNamesIsValid() || !keyGenerationAlgorithmIsValid()) {
            throw new CredentialManagerInvalidEntityException("Name or Subject or EntityProfileName are empty");
        }
    }

    private void validateForUpdate() throws CredentialManagerInvalidEntityException {
        if (!(entityIsValid()
                || idIsValid() && nameIsValid() && subjectIsValid() && entityProfileNamesIsValid() && keyGenerationAlgorithmIsValid())) {
            throw new CredentialManagerInvalidEntityException("Id or Name or Subject or EntityProfileName or KeyGenerationAlgorithm are empty");
        }
    }

    private boolean nameIsValid() {
        return name != null && !name.isEmpty();
    }

    private boolean idIsValid() {
        return id != null;
    }

    private boolean entityProfileNamesIsValid() {
        return !entityProfileName.isEmpty() && !entityProfileName.equals("");
    }

    private boolean subjectIsValid() {
        return subject != null;
    }

    private boolean entityIsValid() {
        return pkiEntity != null && pkiEntity.getEntityInfo() != null && pkiEntity.getEntityInfo().getName() != null
                && !pkiEntity.getEntityInfo().getName().isEmpty() && pkiEntity.getEntityInfo().getSubject() != null
                && !pkiEntity.getEntityProfile().getName().isEmpty();
    }

    private boolean keyGenerationAlgorithmIsValid() {
        return keyGenerationAlgorithm != null && keyGenerationAlgorithm.getName() != null && !keyGenerationAlgorithm.getName()
                .isEmpty();
    }
}
