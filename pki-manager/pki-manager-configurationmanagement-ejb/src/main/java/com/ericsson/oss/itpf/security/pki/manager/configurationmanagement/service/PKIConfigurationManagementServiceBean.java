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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.service;

import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ConfigurationManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.log.annotation.ErrorLogAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.PKIConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.impl.AlgorithmConfigurationManager;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.impl.EntityCategoryConfigurationManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.InvalidConfigurationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;

/**
 * Service for PKI configuration management.
 * 
 * The below are the operations provided.
 * 
 * <ul>
 * <li>Retrieving algorithms available</li>
 * <li>Retrieving supported algorithms</li>
 * <li>Retrieve algorithm by name and key size, applicable for key generation algorithms</li>
 * <li>Update algorithms, it shall be possible to make algorithm as enable/disable</li>
 * <li>Retrieve algorithms by name</li>
 * </ul>
 * 
 * @author xprabil
 */
@Profiled
@Stateless
@EServiceQualifier("1.0.0")
@ErrorLogAnnotation()
public class PKIConfigurationManagementServiceBean implements PKIConfigurationManagementService {

    @Inject
    Logger logger;

    @Inject
    public AlgorithmConfigurationManager algorithmConfigurationManager;

    @Inject
    ConfigurationManagementAuthorizationManager configurationManagementAuthorizationManager;

    @Inject
    EntityCategoryConfigurationManager entityCategoryConfigurationManager;

    @Inject
    private SystemRecorder systemRecorder;

    @Override
    public List<Algorithm> getAlgorithmsByType(final AlgorithmType... algorithmTypes) throws AlgorithmNotFoundException, PKIConfigurationServiceException {

        configurationManagementAuthorizationManager.authorizeAlgorithmConfigurationOperations(ActionType.READ);

        logger.debug("algorithms by type {} ", new Object[] { algorithmTypes });

        final List<Algorithm> algorithmList = algorithmConfigurationManager.getAlgorithmsByType(algorithmTypes);

        logger.debug("{} number of algorithms exists in the system",

        algorithmList.size());

        return algorithmList;
    }

    @Override
    public List<Algorithm> getSupportedAlgorithmsByType(final AlgorithmType... algorithmTypes) throws AlgorithmNotFoundException, PKIConfigurationServiceException {

        configurationManagementAuthorizationManager.authorizeAlgorithmConfigurationOperations(ActionType.READ);

        logger.debug("supported algorithms by type {} ", new Object[] { algorithmTypes });

        final List<Algorithm> algorithmList = algorithmConfigurationManager.getSupportedAlgorithmsByType(algorithmTypes);

        logger.debug("{} number of algorithms supported in the system", algorithmList.size());

        return algorithmList;
    }

    @Override
    public void updateAlgorithms(final List<Algorithm> algorithms) throws AlgorithmNotFoundException, InvalidConfigurationException, PKIConfigurationServiceException {
        boolean isComplete = false;

        try {
            configurationManagementAuthorizationManager.authorizeAlgorithmConfigurationOperations(ActionType.UPDATE);

            for (final Algorithm algorithm : algorithms) {
                if (algorithm.isSupported()) {
                    logger.debug("Enabling {} ", algorithm);
                } else {
                    logger.debug("Disbling {} ", algorithm);
                }
            }

            algorithmConfigurationManager.updateAlgorithms(algorithms);
            isComplete = true;
        } finally {
            generateAlgorithmUpdateEvent(algorithms, isComplete);
        }
    }

    /**
     * This method provides DDC/DDP information for the algorithms update
     * 
     * @param algorithms
     */
    private void generateAlgorithmUpdateEvent(final List<Algorithm> algorithms, final boolean isSuccess) {
        final String status = isSuccess ? "SUCCESS" : "FAILURE";

        for (final Algorithm algorithm : algorithms) {
            final String operationType = algorithm.isSupported() ? "ENABLED" : "DISABLED";
            final String algorithmType = (algorithm.getType() == null ? "-" : algorithm.getType().toString());
            systemRecorder.recordEvent("CONFIGURATIONMANAGEMENT.UPDATE_ALGORITHMS", EventLevel.COARSE, "PKI", "PKIManager",
                    "Configuration [Algorithm Name=" + algorithm.getName() + ", KeySize=" + algorithm.getKeySize() + ", AlgorithmType=" + algorithmType + ", OperationType=" + operationType + ", Status="
                            + status + "]");
        }
    }

    @Override
    public Algorithm getAlgorithmByNameAndKeySize(final String name, final Integer keySize) throws AlgorithmNotFoundException, PKIConfigurationServiceException {

        configurationManagementAuthorizationManager.authorizeAlgorithmConfigurationOperations(ActionType.READ);

        logger.debug("algorithm by name {} and key size {}", name, keySize);

        final Algorithm algorithm = algorithmConfigurationManager.getAlgorithmByNameAndKeySize(name, keySize);

        logger.debug("returned {}", algorithm);

        return algorithm;
    }

    @Override
    public List<Algorithm> getAlgorithmsByName(final String algorithmName) throws AlgorithmNotFoundException, PKIConfigurationServiceException {

        configurationManagementAuthorizationManager.authorizeAlgorithmConfigurationOperations(ActionType.READ);

        logger.debug("algorithms by name {}", algorithmName);

        final List<Algorithm> algorithmList = algorithmConfigurationManager.getAlgorithmsByName(algorithmName);

        logger.debug("{} number of algorithms with the given name ", algorithmList.size());

        return algorithmList;
    }

    @Override
    public EntityCategory createCategory(final EntityCategory entityCategory) throws EntityCategoryAlreadyExistsException, InvalidEntityCategoryException, PKIConfigurationServiceException {

        configurationManagementAuthorizationManager.authorizeEntityCategoryOperations(ActionType.CREATE);

        logger.debug("Creating entity category ", entityCategory.getName());

        final EntityCategory createdEntityCategory = entityCategoryConfigurationManager.createEntityCategory(entityCategory);

        logger.debug("Created {} with ID: {}", entityCategory.getName(), createdEntityCategory.getId());

        return createdEntityCategory;
    }

    @Override
    public void deleteCategory(final EntityCategory category) throws EntityCategoryNotFoundException, EntityCategoryInUseException, PKIConfigurationServiceException {

        configurationManagementAuthorizationManager.authorizeEntityCategoryOperations(ActionType.DELETE);

        logger.debug("Deleting {}", category.getName());

        entityCategoryConfigurationManager.deleteEntityCategory(category);

        logger.debug("Deleted {}", category.getName());

    }

    @Override
    public EntityCategory getCategory(final EntityCategory category) throws EntityCategoryNotFoundException, PKIConfigurationServiceException {

        configurationManagementAuthorizationManager.authorizeEntityCategoryOperations(ActionType.READ);

        logger.debug("Fetching entity category of Name {}", category.getName());

        final EntityCategory entityCategoryFound = entityCategoryConfigurationManager.getEntityCategory(category);

        logger.debug("Fetched entity category with ID: {}", entityCategoryFound.getId());

        return entityCategoryFound;
    }

    @Override
    public EntityCategory updateCategory(final EntityCategory entityCategory) throws EntityCategoryAlreadyExistsException, InvalidEntityCategoryException, PKIConfigurationServiceException {

        configurationManagementAuthorizationManager.authorizeEntityCategoryOperations(ActionType.UPDATE);

        logger.debug("Updating Entity category with Name {}", entityCategory.getName());

        final EntityCategory entityCategoryUpdated = entityCategoryConfigurationManager.updateEntityCategory(entityCategory);

        logger.debug("Updated {} with ID: {}", entityCategory.getName(), entityCategory.getId());
        return entityCategoryUpdated;
    }

    @Override
    public boolean isCategoryNameAvailable(final String categoryName) throws PKIConfigurationServiceException {

        configurationManagementAuthorizationManager.authorizeIsCategoryNameAvailable();

        return entityCategoryConfigurationManager.isNameAvailable(categoryName);
    }

    @Override
    public List<EntityCategory> listAllEntityCategories() throws PKIConfigurationServiceException {

        configurationManagementAuthorizationManager.authorizeEntityCategoryOperations(ActionType.READ);
        final List<EntityCategory> entityCategories = entityCategoryConfigurationManager.getEntityCategories();

        logger.debug("Exported categories :: {}", entityCategories);
        return entityCategories;
    }

}
