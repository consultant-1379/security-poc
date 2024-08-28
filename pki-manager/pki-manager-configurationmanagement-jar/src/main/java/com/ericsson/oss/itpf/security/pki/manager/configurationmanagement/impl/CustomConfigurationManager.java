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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.impl;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.CustomConfigurationPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationInvalidException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfigurations;

public class CustomConfigurationManager {

    @Inject
    Logger logger;

    @Inject
    CustomConfigurationPersistenceHandler customConfigurationPersistenceHandler;

    /**
     * API for creating {@link CustomConfiguration}
     *
     * @param customConfiguration
     *            {@link CustomConfiguration} instance that is to be created.
     *
     * @return Instance of created {@link CustomConfiguration}
     *
     * @throws CustomConfigurationAlreadyExistsException
     *             thrown when custom configuration with same name already exists.
     * @throws CustomConfigurationInvalidException
     *             thrown when custom configuration if name or owner are empty or null.
     * @throws CustomConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public CustomConfiguration createCustomConfiguration(CustomConfiguration customConfiguration)
            throws CustomConfigurationAlreadyExistsException, CustomConfigurationInvalidException, CustomConfigurationServiceException {

        logger.debug("creating custom configuration with Name: {} and Owner: {}", customConfiguration.getName(), customConfiguration.getOwner());

        validate(customConfiguration);

        customConfiguration = customConfigurationPersistenceHandler.createCustomConfiguration(customConfiguration);

        logger.info("Custom Configuration created with ID: {}", customConfiguration.getId());

        logger.debug("Custom Configuration Created: {}", customConfiguration);
        return customConfiguration;
    }

    /**
     * API for updating {@link CustomConfiguration}
     *
     * @param customConfiguration
     *            {@link CustomConfiguration} instance that is to be updated.
     *
     * @return Instance of updated {@link CustomConfiguration}
     *
     * @throws CustomConfigurationNotFoundException
     *             thrown when custom configuration is not found.
     * @throws CustomConfigurationInvalidException
     *             thrown when custom configuration if name or owner are empty or null.
     * @throws CustomConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public CustomConfiguration updateCustomConfiguration(CustomConfiguration customConfiguration)
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        logger.debug("Updating custom configuration with Name: {} and Owner: {}", customConfiguration.getName(), customConfiguration.getOwner());
        validate(customConfiguration);
        customConfiguration = customConfigurationPersistenceHandler.updateCustomConfiguration(customConfiguration);
        logger.debug("Custom configuration with Name: {} and Owner: {} updated", customConfiguration.getName(), customConfiguration.getOwner());
        return customConfiguration;
    }


    /**
     * API to get the custom configuration based on the custom configuration name and owner.
     *
     * @param customConfiguration
     *            {@link CustomConfiguration} instance with name.
     *
     * @return CustomConfiguration object of type {@link CustomConfiguration}
     *
     * @throws CustomConfigurationNotFoundException
     *             thrown when custom configuration is not found.
     * @throws CustomConfigurationInvalidException
     *             thrown when custom configuration if name or owner are empty or null.
     * @throws CustomConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public CustomConfiguration getCustomConfiguration(CustomConfiguration customConfiguration)
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        logger.debug("Retrieving custom configuration with Name: {} Owner: {}", customConfiguration.getName(), customConfiguration.getOwner());
        validate(customConfiguration);
        customConfiguration = customConfigurationPersistenceHandler.getCustomConfiguration(customConfiguration);
        logger.debug("Custom configuration with Name: {} Owner: {} retrieved ", customConfiguration.getName(), customConfiguration.getOwner());
        return customConfiguration;
    }

    /**
     * API used to delete the custom configuration based on the name and owner.
     *
     * @param customConfiguration
     *            {@link CustomConfiguration} instance with name and owner.
     *
     * @return void
     *
     * @throws CustomConfigurationNotFoundException
     *             thrown when given custom configuration is not found.
     * @throws CustomConfigurationInvalidException
     *             thrown when custom configuration if name or owner are empty or null.
     * @throws CustomConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public void deleteCustomConfiguration(final CustomConfiguration customConfiguration)
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        validate(customConfiguration);
        logger.debug("Deleting custom configuration with Name:{} Owner:{}", customConfiguration.getName(), customConfiguration.getOwner());
        customConfigurationPersistenceHandler.deleteCustomConfiguration(customConfiguration);
        logger.debug("Custom configuration with Name: {} Owner: {} deleted", customConfiguration.getName(), customConfiguration.getOwner());
    }

    /**
     * API for checking whether the given Custom Configuration exists in the database.
     *
     * @param customConfiguration
     *            CustomConfiguraion
     *
     * @return boolean returns true/false based on whether the custom configuration exists with the given name and owner.
     *
     * @throws CustomConfigurationInvalidException
     *             thrown when custom configuration if name or owner are empty or null.
     * @throws CustomConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public boolean isPresentCustomConfiguration(final CustomConfiguration customConfiguration) throws CustomConfigurationInvalidException, CustomConfigurationServiceException {
        validate(customConfiguration);
        logger.debug("Checking if custom configuration with name {} owner {} is present", customConfiguration.getName(), customConfiguration.getOwner());
        return customConfigurationPersistenceHandler.isPresentCustomConfiguration(customConfiguration);
    }

    private void validate(final CustomConfiguration customConfiguration) throws CustomConfigurationInvalidException {
        if (customConfiguration.getName() == null) {
            throw new CustomConfigurationInvalidException("Name is null");
        } else if (customConfiguration.getName().isEmpty()) {
            throw new CustomConfigurationInvalidException("Name is empty");
        }
        if (customConfiguration.getOwner() == null) {
            throw new CustomConfigurationInvalidException("Owner is null");
        } else if (customConfiguration.getOwner().isEmpty()) {
            throw new CustomConfigurationInvalidException("Owner is empty");
        }
    }

    /**
     * @param customConfigurations
     * @return
     */
    public CustomConfigurations getCustomConfigurations(final CustomConfigurations customConfigurations)
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        final CustomConfigurations customConfigRetrieved = new CustomConfigurations();
        if (customConfigurations != null && customConfigurations.getCustomConfigurations() != null) {
            final List<CustomConfiguration> customConfigList = new ArrayList<>();
            for (CustomConfiguration customConfiguration : customConfigurations.getCustomConfigurations()) {
                customConfigList.add(getCustomConfiguration(customConfiguration));

            }
            customConfigRetrieved.setCustomConfigurations(customConfigList);
        }
        return customConfigRetrieved;
    }

    /**
     * @param customConfigurations
     * @return
     */
    public CustomConfigurations createCustomConfigurations(final CustomConfigurations customConfigurations) {
        final CustomConfigurations customConfigCreated = new CustomConfigurations();
        if (customConfigurations != null && customConfigurations.getCustomConfigurations() !=null) {
            final List<CustomConfiguration> customConfigList = new ArrayList<>();
            for (CustomConfiguration customConfiguration : customConfigurations.getCustomConfigurations()) {
                customConfigList.add(createCustomConfiguration(customConfiguration));

            }
            customConfigCreated.setCustomConfigurations(customConfigList);
        }
        return customConfigCreated;
    }

    /**
     * @param customConfigurations
     * @return
     */
    public CustomConfigurations updateCustomConfigurations(final CustomConfigurations customConfigurations) {
        final CustomConfigurations customConfigUpdated = new CustomConfigurations();
        if (customConfigurations != null && customConfigurations.getCustomConfigurations() !=null) {
            final List<CustomConfiguration> customConfigList = new ArrayList<>();
            for (CustomConfiguration customConfiguration : customConfigurations.getCustomConfigurations()) {
                if (isPresentCustomConfiguration(customConfiguration)) {
                    customConfigList.add(updateCustomConfiguration(customConfiguration));
                } else {
                    customConfigList.add(createCustomConfiguration(customConfiguration));
                }
            }
            customConfigUpdated.setCustomConfigurations(customConfigList);
        }
        return customConfigUpdated;
    }

    /**
     * @param customConfigurations
     */
    public void deleteCustomConfigurations(final CustomConfigurations customConfigurations) {
        if (customConfigurations != null && customConfigurations.getCustomConfigurations() !=null) {
            for (CustomConfiguration customConfiguration : customConfigurations.getCustomConfigurations()) {
                deleteCustomConfiguration(customConfiguration);
            }
        }

    }
}
