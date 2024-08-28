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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration;

import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.CustomConfigurationMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CustomConfigurationData;

/**
 * This class is responsible for DB CRUD Operation. Each method is responsible for
 * <ul>
 * <li>Mapping API Model to JPA Entity</li>
 * <li>Do CRUD Operation on JPA Entity</li>
 * <li>Convert back to API Model if required</li>
 * </ul>
 *
 */
public class CustomConfigurationPersistenceHandler {

    @Inject
    private Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CustomConfigurationMapper customConfigurationMapper;

    private static final String CUSTOM_CONFIGURATION_NAME = "name";
    private static final String CUSTOM_CONFIGURATION_OWNER = "owner";

    /**
     * @param customConfiguration
     * @return CustomConfiguration
     */
    public CustomConfiguration createCustomConfiguration(final CustomConfiguration customConfiguration) throws CustomConfigurationAlreadyExistsException, CustomConfigurationServiceException {
        CustomConfiguration custConfiguration;
        if (isPresentCustomConfiguration(customConfiguration)) {
            logger.error("Custom Configuration with name {} and owner {} already exists", customConfiguration.getName(), customConfiguration.getOwner());
            throw new CustomConfigurationAlreadyExistsException(ErrorMessages.OCCURED_IN_CUSTOM_CONFIGURATION_ALREADY_EXISTS);
        }
        try {
            final CustomConfigurationData customConfigurationData = customConfigurationMapper.fromAPIToModel(customConfiguration);
            persistenceManager.createEntity(customConfigurationData);
            custConfiguration = getCustomConfiguration(customConfiguration);
        } catch (final Exception exception) {
            logger.error("Unexpected Error in creating custom configuration. {}", exception.getMessage());
            throw new CustomConfigurationServiceException(ErrorMessages.OCCURED_IN_CREATING_CUSTOM_CONFIGURATION, exception);
        }
        return custConfiguration;
    }

    /**
     * @param customConfiguration
     * @return CustomConfigurationData
     */
    private CustomConfigurationData getCustConfiguration(final CustomConfiguration customConfiguration) throws CustomConfigurationServiceException {
        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(CUSTOM_CONFIGURATION_NAME, customConfiguration.getName());
        input.put(CUSTOM_CONFIGURATION_OWNER, customConfiguration.getOwner());
        CustomConfigurationData customConfigurationData = null;

        try {
            customConfigurationData = persistenceManager.findEntityWhere(CustomConfigurationData.class, input);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error when fetching custom configuration with name ", customConfiguration.getName(), " and  owner ", customConfiguration.getOwner());
            throw new CustomConfigurationServiceException(persistenceException);
        }
        return customConfigurationData;
    }

    /**
     * @param customConfiguration
     * @return CustomConfiguration
     */
    public CustomConfiguration updateCustomConfiguration(final CustomConfiguration customConfiguration) throws CustomConfigurationNotFoundException, CustomConfigurationServiceException {
        CustomConfiguration custConfiguration;
        final CustomConfigurationData customConfigurationDataActual = getCustConfiguration(customConfiguration);

        if (customConfigurationDataActual == null) {
            throw new CustomConfigurationNotFoundException(ErrorMessages.OCCURED_IN_CUSTOM_CONFIGURATION_NOT_FOUND);
        }
        try {
            final CustomConfigurationData customConfigurationData = customConfigurationMapper.fromAPIToModel(customConfiguration);
            customConfigurationData.setId(customConfigurationDataActual.getId());
            persistenceManager.updateEntity(customConfigurationData);
            custConfiguration = getCustomConfiguration(customConfiguration);

        } catch (final PersistenceException ex) {
            logger.error("Transaction error in Custom Configuration update with name {} and owner {} - {}", customConfiguration.getName(), customConfiguration.getOwner(),
 ex.getMessage());

            throw new CustomConfigurationServiceException(ErrorMessages.OCCURED_IN_UPDATING_CUSTOM_CONFIGURATION, ex);
        }
        return custConfiguration;
    }

    /**
     * @param customConfiguration
     * @return CustomConfiguration
     */
    public CustomConfiguration getCustomConfiguration(final CustomConfiguration customConfiguration) throws CustomConfigurationNotFoundException, CustomConfigurationServiceException {
        final CustomConfigurationData customConfigurationData = getCustConfiguration(customConfiguration);
        if (customConfigurationData == null) {
            logger.error("Custom configuration not found");
            throw new CustomConfigurationNotFoundException();
        }
        return customConfigurationMapper.toAPIFromModel(customConfigurationData);
    }

    /**
     * @param customConfiguration
     */
    public void deleteCustomConfiguration(final CustomConfiguration customConfiguration) throws CustomConfigurationNotFoundException, CustomConfigurationServiceException {

        final CustomConfigurationData customConfigurationData = getCustConfiguration(customConfiguration);

        try {
            if (customConfigurationData != null) {
                persistenceManager.deleteEntity(customConfigurationData);
            } else {
                logger.error("Custom configuration not found");
                throw new CustomConfigurationNotFoundException();
            }
        } catch (final PersistenceException ex) {
            logger.error("Transaction error occurred while deleting Custom Configuration  with name {} and owner {} - {}", customConfiguration.getName(), customConfiguration.getOwner(),
                    ex.getMessage());
            throw new CustomConfigurationServiceException(ErrorMessages.OCCURED_IN_DELETING_CUSTOM_CONFIGURATION, ex);
        }

    }

    /**
     * @param customConfiguration
     * @return boolean
     */
    public boolean isPresentCustomConfiguration(final CustomConfiguration customConfiguration) throws CustomConfigurationServiceException {

        final CustomConfigurationData customConfigurationData = getCustConfiguration(customConfiguration);
        if (customConfigurationData != null) {
            return true;
        }
        return false;
    }

}
