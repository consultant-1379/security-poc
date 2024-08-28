package com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.service;

import java.util.ArrayList;
import java.util.List;

import javax.ejb.*;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.EntityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.validators.CAValidator;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.validators.EntityValidator;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;

/**
 * Session Bean implementation class EntitiesBulkImportLocalServiceBean
 */
@Stateless
@LocalBean
public class BulkImportLocalServiceBean {

    @Inject
    EntityModelMapper entityMapper;

    @Inject
    CertificateAuthorityModelMapper cAEntityMapper;

    @Inject
    EntityPersistenceHandler entityPersistenceHandler;

    @Inject
    CAEntityPersistenceHandler caEntityPersistenceHandler;

    @Inject
    CAValidator cAValidator;

    @Inject
    EntityValidator entityValidator;

    @Inject
    Logger logger;

    private static final String FOR_THE_ENTITY = " in PKICore for the Entity- ";
    private static final String FOR_THE_CAENTITY = " in PKICore for for the CA Entity- ";

    /**
     * Method used to import EntityInfo in Bulk
     *
     * @param entityInfoList
     *            of EntityInfo to create
     * @return List
     * @throws CoreEntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws CoreEntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public List<EntityInfo> importEntityInfo(final List<EntityInfo> entityInfoList) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        final List<EntityInfoData> validEntityInfoDatas = validateEntityInfoList(entityInfoList);

        for (final EntityInfoData entityInfoData : validEntityInfoDatas) {
            try {
                entityPersistenceHandler.persistEntityInfo(entityInfoData);
            } catch (final CoreEntityAlreadyExistsException alreadyExistsException) {
                logger.debug("Error  while Persisting the EntityInfo ", alreadyExistsException);
                logger.error("Error  while Persisting the EntityInfo");
                throw new CoreEntityAlreadyExistsException(FOR_THE_ENTITY + entityInfoData.getName());
            } catch (final CoreEntityServiceException entityServiceException) {
                logger.debug("Error  while Persisting the EntityInfo ", entityServiceException);
                logger.error("Error  while Persisting the EntityInfo");
                throw new CoreEntityServiceException(FOR_THE_ENTITY + entityInfoData.getName());
            }
        }
        return entityInfoList;
    }

    private List<EntityInfoData> validateEntityInfoList(final List<EntityInfo> entityInfoList) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        final List<EntityInfoData> validEntityInfoDatas = new ArrayList<EntityInfoData>();
        for (final EntityInfo entityInfo : entityInfoList) {
            validEntityInfoDatas.add(getValidEntityInfoData(entityInfo));
        }
        return validEntityInfoDatas;
    }

    /**
     * Method used to import CertificateAuthority in Bulk
     *
     * @param certificateAuthorityList
     *            of CertificateAuthority to create
     * @return List<CertificateAuthority>
     * @throws CoreEntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws CoreEntityServiceException
     *             thrown when any internal Database errors.
     */
    public List<CertificateAuthority> importCertificateAuthority(final List<CertificateAuthority> certificateAuthorityList) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        final List<CertificateAuthorityData> validCertificateAuthorityModels = validateCertificateAuthority(certificateAuthorityList);
        for (final CertificateAuthorityData certificateAuthorityData : validCertificateAuthorityModels) {
            try {
                caEntityPersistenceHandler.persistCertificateAuthorityData(certificateAuthorityData);
            } catch (final CoreEntityAlreadyExistsException alreadyExistsException) {
                logger.debug("Error  while Persisting the CertificateAuthority ", alreadyExistsException);
                logger.error("Error  while Persisting the CertificateAuthority");
                throw new CoreEntityAlreadyExistsException(FOR_THE_CAENTITY + certificateAuthorityData.getName());
            }
        }
        return certificateAuthorityList;
    }

    private List<CertificateAuthorityData> validateCertificateAuthority(final List<CertificateAuthority> certificateAuthorityList) {

        final List<CertificateAuthorityData> validCertificateAuthorityModels = new ArrayList<CertificateAuthorityData>();
        for (final CertificateAuthority certificateAuthority : certificateAuthorityList) {
            validCertificateAuthorityModels.add(getValidCertificateAuthorityData(certificateAuthority));
        }
        return validCertificateAuthorityModels;
    }

    /**
     * Method to validate EntityInfo and map the EntityInfo to JPA Model
     *
     * @param entityInfo
     * @return EntityInfoData
     * @throws CoreEntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws CoreEntityServiceException
     *             thrown when any internal Database errors.
     */
    private EntityInfoData getValidEntityInfoData(final EntityInfo entityInfo) {

        final EntityInfoData entityInfoData;
        try {
            entityValidator.validateEntity(entityInfo, OperationType.CREATE);
            entityInfoData = entityMapper.fromAPIToModel(entityInfo, OperationType.CREATE);
        } catch (final CoreEntityAlreadyExistsException alreadyExistsException) {
            logger.debug("Error  while validating the EntityInfo ", alreadyExistsException);
            logger.error("Error  while validating the EntityInfo");
            throw new CoreEntityAlreadyExistsException(FOR_THE_ENTITY + entityInfo.getName());
        } catch (final PersistenceException persistenceexception) {
            logger.error("Error  while validating the EntityInfo", persistenceexception.getMessage());
            throw new CoreEntityServiceException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, persistenceexception);
        }
        logger.debug("validation in core done with ID:: {} EntityInfo::{}", entityInfo.getId(), entityInfo.getName());
        return entityInfoData;
    }

    /**
     * Method to validate CertificateAuthority and map the CertificateAuthority to JPA Model
     *
     * @param certificateAuthority
     * @return CertificateAuthorityData
     * @throws CoreEntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     */
    private CertificateAuthorityData getValidCertificateAuthorityData(final CertificateAuthority certificateAuthority) {

        final CertificateAuthorityData certificateAuthorityData;
        try {
            cAValidator.validateCAEntity(certificateAuthority, OperationType.CREATE);
            certificateAuthorityData = cAEntityMapper.fromAPIModel(certificateAuthority, OperationType.CREATE);
        } catch (final CoreEntityAlreadyExistsException alreadyExistsException) {
            logger.debug("Error  while validating the CertificateAuthorityData ", alreadyExistsException);
            logger.error("Error  while validating the CertificateAuthorityData");
            throw new CoreEntityAlreadyExistsException(FOR_THE_CAENTITY + certificateAuthority.getName());
        }
        logger.debug("validation in core done with ID:: {} certificateAuthority::{}", certificateAuthority.getId(), certificateAuthority.getName());
        return certificateAuthorityData;
    }

}
