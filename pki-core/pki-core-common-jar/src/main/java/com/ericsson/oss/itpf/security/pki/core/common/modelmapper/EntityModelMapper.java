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
package com.ericsson.oss.itpf.security.pki.core.common.modelmapper;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;

public class EntityModelMapper {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CertificateAuthorityModelMapper caEntityMapper;

    private static final String NAME_PATH = "name";

    /**
     * Converting {@link EntityInfo} API model to {@link EntityData} entity.
     * 
     * @param entityInfo
     *            object that to be converted to JPA entity.
     * @param operationType
     * @return converted {@link EntityData} entity.
     * @throws PersistenceException
     *             Thrown in case of db errors
     */
    public EntityInfoData fromAPIToModel(final EntityInfo entityInfo, final OperationType operationType) throws PersistenceException {

        logger.debug("Mapping EntityInfo domain model to EntityData entity for {}", entityInfo.getName());

        EntityInfoData entityInfoData = null;
        CertificateAuthorityData issuerData = null;

        if (operationType.equals(OperationType.UPDATE)) {
            entityInfoData = persistenceManager.findEntity(EntityInfoData.class, entityInfo.getId());
        }
        if (entityInfoData == null) {
            entityInfoData = new EntityInfoData();
        }
        entityInfoData.setId(entityInfo.getId());
        entityInfoData.setName(entityInfo.getName());
        entityInfoData.setStatus(entityInfo.getStatus());
        if (entityInfo.getSubject() != null) {
            entityInfoData.setSubjectDN(entityInfo.getSubject().toASN1String());
        }
        if (entityInfo.getSubjectAltName() != null) {
            entityInfoData.setSubjectAltName(JsonUtil.getJsonFromObject(entityInfo.getSubjectAltName()));
        }
        if (entityInfo.getIssuer() != null && entityInfo.getIssuer().getName() != null) {
            issuerData = persistenceManager.findEntityByName(CertificateAuthorityData.class, entityInfo.getIssuer().getName(), NAME_PATH);
        }
        entityInfoData.setIssuerCA(issuerData);

        logger.debug("Mapped EntityData for entity {}", entityInfoData.getName());
        return entityInfoData;
    }

    /**
     * Maps the Entity JPA model to its corresponding API model
     * 
     * @param entityInfoData
     *            EntityData Object which should be converted to API model Entity
     * 
     * @return Returns the API model of the given JPA model
     * 
     * @throws InvalidCertificateException
     *             Thrown when Invalid certificate is found for entity.
     * 
     * @throws InvalidCRLGenerationInfoException
     *             thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     * 
     */
    public EntityInfo toAPIFromModel(final EntityInfoData entityInfoData) throws InvalidCertificateException, InvalidCRLGenerationInfoException {

        logger.debug("Mapping EntityData entity to Entity domain model for {}", entityInfoData.getName());

        final EntityInfo entityInfo = new EntityInfo();

        entityInfo.setId(entityInfoData.getId());
        entityInfo.setName(entityInfoData.getName());
        if (entityInfoData.getSubjectDN() != null) {
            final Subject subject = new Subject();
            entityInfo.setSubject(subject.fromASN1String(entityInfoData.getSubjectDN()));
        }
        if (entityInfoData.getSubjectAltName() != null) {
            entityInfo.setSubjectAltName(JsonUtil.getObjectFromJson(SubjectAltName.class, entityInfoData.getSubjectAltName()));
        }
        entityInfo.setStatus(entityInfoData.getStatus());

        if (entityInfoData.getIssuerCA() != null) {
            entityInfo.setIssuer(caEntityMapper.toAPIModel(entityInfoData.getIssuerCA()));
        }

        logger.debug("Mapped Entity domain model for  {}", entityInfo.getName());

        return entityInfo;
    }

}
