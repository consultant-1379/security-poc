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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.service;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ConfigurationManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.log.annotation.ErrorLogAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.CustomConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.impl.CustomConfigurationManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationInvalidException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfigurations;

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
public class CustomConfigurationManagementServiceBean implements CustomConfigurationManagementService {

    @Inject
    Logger logger;

    @Inject
    CustomConfigurationManager customConfigurationManager;

    @Inject
    ConfigurationManagementAuthorizationManager configurationManagementAuthorizationManager;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.CustomConfigurationManagementService#getCustomConfiguration(com.ericsson.oss.itpf.security.pki.manager.model.
     * CustomConfiguration)
     */
    @Override
    public CustomConfiguration getCustomConfiguration(final CustomConfiguration customConfiguration)
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        configurationManagementAuthorizationManager.authorizeCustomConfigurationOperations(ActionType.READ);

        logger.info("Fetching Custom Configuration with Name {} and Owner", customConfiguration.getName(), customConfiguration.getOwner());

        final CustomConfiguration customConfigurationFound = customConfigurationManager.getCustomConfiguration(customConfiguration);

        logger.info("Fetched custom configuration with ID: {}", customConfigurationFound.getId());
        return customConfigurationFound;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.CustomConfigurationManagementService#createCustomConfiguration(com.ericsson.oss.itpf.security.pki.manager.model.
     * CustomConfiguration)
     */
    @Override
    public CustomConfiguration createCustomConfiguration(final CustomConfiguration customConfiguration)
            throws CustomConfigurationAlreadyExistsException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        configurationManagementAuthorizationManager.authorizeCustomConfigurationOperations(ActionType.CREATE);

        logger.info("Creating custom configuration Name {} Owner {} ", customConfiguration.getName(), customConfiguration.getOwner());

        final CustomConfiguration createdCustomConfiguration = customConfigurationManager.createCustomConfiguration(customConfiguration);

        logger.info("Created {} with ID: {}", customConfiguration.getName(), createdCustomConfiguration.getId());

        return createdCustomConfiguration;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.CustomConfigurationManagementService#updateCustomConfiguration(com.ericsson.oss.itpf.security.pki.manager.model.
     * CustomConfiguration)
     */
    @Override
    public CustomConfiguration updateCustomConfiguration(final CustomConfiguration customConfiguration)
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        configurationManagementAuthorizationManager.authorizeCustomConfigurationOperations(ActionType.UPDATE);

        logger.info("Updating Custiom Configuration with Name {} and Owner {}", customConfiguration.getName(), customConfiguration.getOwner());

        final CustomConfiguration customConfigurationUpdated = customConfigurationManager.updateCustomConfiguration(customConfiguration);

        logger.info("Updated {} with ID: {}", customConfiguration.getName(), customConfigurationUpdated.getId());
        return customConfigurationUpdated;

    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.CustomConfigurationManagementService#deleteCustomConfiguration(com.ericsson.oss.itpf.security.pki.manager.model.
     * CustomConfiguration)
     */
    @Override
    public void deleteCustomConfiguration(final CustomConfiguration customConfiguration)
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {

        configurationManagementAuthorizationManager.authorizeCustomConfigurationOperations(ActionType.DELETE);

        logger.info("Deleting {} {} ", customConfiguration.getName(), customConfiguration.getOwner());

        customConfigurationManager.deleteCustomConfiguration(customConfiguration);

        logger.info("Deleted {} {}", customConfiguration.getName(), customConfiguration.getOwner());
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.CustomConfigurationManagementService#isPresentCustomConfiguration(com.ericsson.oss.itpf.security.pki.manager.model.
     * CustomConfiguration)
     */
    @Override
    public Boolean isPresentCustomConfiguration(final CustomConfiguration customConfiguration) throws CustomConfigurationInvalidException, CustomConfigurationServiceException {

        configurationManagementAuthorizationManager.authorizeIsPresentCustomConfiguration();

        return customConfigurationManager.isPresentCustomConfiguration(customConfiguration);
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.CustomConfigurationManagementService#getCustomConfigurations(com.ericsson.oss.itpf.security.pki.manager.model.
     * CustomConfigurations)
     */
    @Override
    public CustomConfigurations getCustomConfigurations(final CustomConfigurations customConfigurations)
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        configurationManagementAuthorizationManager.authorizeCustomConfigurationOperations(ActionType.READ);

        logger.info("Fetching Custom Configuration");

        final CustomConfigurations customConfigurationsFound = customConfigurationManager.getCustomConfigurations(customConfigurations);

        return customConfigurationsFound;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.CustomConfigurationManagementService#createCustomConfigurationInfo(com.ericsson.oss.itpf.security.pki.manager.model.
     * CustomConfigurations)
     */
    @Override
    public CustomConfigurations createCustomConfigurations(final CustomConfigurations customConfigurations) throws CustomConfigurationInvalidException, CustomConfigurationServiceException {
        configurationManagementAuthorizationManager.authorizeCustomConfigurationOperations(ActionType.CREATE);
        logger.info("Creating Custom Configuration");
        final CustomConfigurations createdCustomConfigurations = customConfigurationManager.createCustomConfigurations(customConfigurations);
        return createdCustomConfigurations;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.CustomConfigurationManagementService#updateCustomConfigurationInfo(com.ericsson.oss.itpf.security.pki.manager.model.
     * CustomConfigurations)
     */
    @Override
    public CustomConfigurations updateCustomConfigurations(final CustomConfigurations customConfigurations) throws CustomConfigurationInvalidException, CustomConfigurationServiceException {
        configurationManagementAuthorizationManager.authorizeCustomConfigurationOperations(ActionType.UPDATE);
        logger.info("Updating Custom Configuration");
        final CustomConfigurations customConfigurationsUpdated = customConfigurationManager.updateCustomConfigurations(customConfigurations);
        return customConfigurationsUpdated;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.CustomConfigurationManagementService#deleteCustomConfigurations(com.ericsson.oss.itpf.security.pki.manager.model.
     * CustomConfigurations)
     */
    @Override
    public void deleteCustomConfigurations(final CustomConfigurations customConfigurations) throws CustomConfigurationInvalidException, CustomConfigurationServiceException {
        configurationManagementAuthorizationManager.authorizeCustomConfigurationOperations(ActionType.DELETE);
        logger.info("Deleting Custom Configuration");
        customConfigurationManager.deleteCustomConfigurations(customConfigurations);
    }

}
