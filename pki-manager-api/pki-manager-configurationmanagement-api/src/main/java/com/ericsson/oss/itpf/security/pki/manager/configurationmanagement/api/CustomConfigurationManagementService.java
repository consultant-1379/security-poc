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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationInvalidException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.CustomConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfiguration;
import com.ericsson.oss.itpf.security.pki.manager.model.CustomConfigurations;

/**
 * Service for Custom configuration management.
 *
 * The below are the operations provided.
 *
 * <ul>
 * <li>Retrieving custom configuration available</li>
 * <li>Add and update custom configuration</li>
 * </ul>
 *
 */
@EService
@Remote
public interface CustomConfigurationManagementService {

    /**
     * Returns the custom configuration for the given name and owner.
     *
     * @param customConfiguration
     *            The {@link CustomConfiguration}.
     * @return the custom configuration for the given name and owner.
     *
     * @throws CustomConfigurationNotFoundException
     *             Throws in case of the custom configuration not found for a give name and owner.
     * @throws CustomConfigurationInvalidException
     *             Throws in case of name or owner are null or empty.
     * @throws CustomConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    CustomConfiguration getCustomConfiguration(CustomConfiguration customConfiguration)
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException;

    /**
     * Returns the custom configuration created for the given name and owner.
     *
     * @param customConfiguration
     *            The {@link CustomConfiguration}.
     * @return the custom configuration created for the given name and owner.
     *
     * @throws CustomConfigurationAlreadyExistsException
     *             Throws in case of the custom configuration info not found for a give name and owner.
     * @throws CustomConfigurationInvalidException
     *             Throws in case of name or owner are null or empty.
     * @throws CustomConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    CustomConfiguration createCustomConfiguration(CustomConfiguration customConfiguration)
            throws CustomConfigurationAlreadyExistsException, CustomConfigurationInvalidException, CustomConfigurationServiceException;

    /**
     * Returns the custom configuration updated for the given name and owner.
     *
     * @param customConfiguration
     *            The {@link CustomConfiguration}.
     * @return the custom configuration updated for the given name and owner.
     *
     * @throws CustomConfigurationNotFoundException
     *             Throws in case of the custom configuration info not found for a give name and owner.
     * @throws CustomConfigurationInvalidException
     *             Throws in case of name or owner are null or empty.
     * @throws CustomConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    CustomConfiguration updateCustomConfiguration(CustomConfiguration customConfiguration)
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException;

    /**
     * Delete the custom configuration for the given name and owner.
     *
     * @param customConfiguration
     *            to delete The {@link CustomConfiguration}.
     *
     * @throws CustomConfigurationNotFoundException
     *             Throws in case of the custom configuration info not found for a give name and owner.
     * @throws CustomConfigurationInvalidException
     *             Throws in case of name or owner are null or empty.
     * @throws CustomConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    void deleteCustomConfiguration(CustomConfiguration customConfiguration) throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException;

    /**
     * Returns if the custom configuration is present for the given name and owner.
     *
     * @param customConfiguration
     *            The {@link CustomConfiguration}.
     * @return if the custom configuration is present for the given name and owner.
     *
     * @throws CustomConfigurationInvalidException
     *             Throws in case of name or owner are null or empty.
     * @throws CustomConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    Boolean isPresentCustomConfiguration(CustomConfiguration customConfiguration) throws CustomConfigurationInvalidException, CustomConfigurationServiceException;

    /**
     * Export custom configurations in bulk manner. It returns the custom configurations based on the specified name and owner. If a custom configuration for a name and owner doesn't exist, it won't
     * be returned.
     *
     * @param customConfigurations
     *            The {@link CustomConfigurations}.
     * @return CustomConfigurations object containing list of custom configuration based on the specified name and owner. *
     *
     * @throws CustomConfigurationInvalidException
     *             Throws in case of at least a custom configuration has name or owner null or empty.
     * @throws CustomConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    CustomConfigurations getCustomConfigurations(CustomConfigurations customConfigurations)
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException;

    /**
     * Returns the custom configurations created for a list of name and owner. If some customConfiguration are already present a CustomConfigurationAlreadyExistsException is thrown.
     *
     * @param customConfigurations
     *            The {@link CustomConfigurations}.
     * @return the custom configurations created for a list of name and owner.
     *
     * @throws CustomConfigurationAlreadyExistsException
     *             Throws in case of the custom configuration info not found for a give name and owner.
     * @throws CustomConfigurationInvalidException
     *             Throws in case of at least a custom configuration has name or owner null or empty.
     * @throws CustomConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    CustomConfigurations createCustomConfigurations(CustomConfigurations customConfigurations)
            throws CustomConfigurationAlreadyExistsException, CustomConfigurationInvalidException, CustomConfigurationServiceException;

    /**
     * Returns the custom configurations updated for a list of name and owner.
     *
     * @param customConfigurations
     *            The {@link CustomConfigurations}.
     * @return the custom configurations updated for a list of name and owner.
     *
     * @throws CustomConfigurationNotFoundException
     *             Throws in case of the custom configuration info not found for a give name and owner.
     * @throws CustomConfigurationInvalidException
     *             Throws in case of at least a custom configuration has name or owner null or empty.
     * @throws CustomConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    CustomConfigurations updateCustomConfigurations(CustomConfigurations customConfigurations) throws CustomConfigurationInvalidException, CustomConfigurationServiceException;

    /**
     * Delete the custom configurations for a list of name and owner.
     *
     * @param customConfigurations
     *            to delete to delete The {@link CustomConfiguration}.
     *
     * @throws CustomConfigurationInvalidException
     *             Throws in case of at least a custom configuration has name or owner null or empty.
     * @throws CustomConfigurationNotFoundException
     *             Throws in case of the custom configuration info not found for a give name and owner.
     * @throws CustomConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    void deleteCustomConfigurations(CustomConfigurations customConfigurations) throws CustomConfigurationInvalidException, CustomConfigurationServiceException;

}