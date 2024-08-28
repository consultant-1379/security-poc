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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api;

import java.util.List;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIConfigurationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.InvalidConfigurationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
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
@EService
@Remote
public interface PKIConfigurationManagementService {

    /**
     * Returns the list of all supported/unsupported algorithms based on algorithm types.
     * 
     * @param algorithmTypes
     *            The {@link AlgorithmType} types.
     * @return List of all algorithms of specified type(s).
     * 
     * @throws AlgorithmNotFoundException
     *             Throws in case of algorithm not found for the given Type.
     * @throws PKIConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    List<Algorithm> getAlgorithmsByType(AlgorithmType... algorithmTypes) throws AlgorithmNotFoundException, PKIConfigurationServiceException;

    /**
     * Returns the list of supported algorithms based on types.
     * 
     * @param algorithmTypes
     *            The {@link AlgorithmType} types.
     * @return List of supported algorithms of specified type(s).
     * 
     * @throws AlgorithmNotFoundException
     *             Throws in case of algorithm not found for the given Type.
     * @throws PKIConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    List<Algorithm> getSupportedAlgorithmsByType(AlgorithmType... algorithmTypes) throws AlgorithmNotFoundException, PKIConfigurationServiceException;

    /**
     * To make Algorithm(s) as supported/unsupported. If trying to update Key Generation algorithm specify both algorithm name and key size. For other type of algorithms only name is required.
     * 
     * @param updateAlgorithms
     *            List of Algorithm objects to make algorithms as supported/unsupported.
     * 
     * @throws AlgorithmNotFoundException
     *             Throws in case of algorithm not found for the given name and key size.
     * @throws InvalidConfigurationException
     *             Thrown when keySize is not provided for updating keyGenerationAlgorithm.
     * @throws PKIConfigurationException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    void updateAlgorithms(List<Algorithm> updateAlgorithms) throws AlgorithmNotFoundException, InvalidConfigurationException, PKIConfigurationServiceException;

    /**
     * Returns the algorithm object based on algorithm name and key size. This method is only for getting key generation type of algorithms.
     * 
     * @param name
     *            The algorithm name.
     * @param keySize
     *            The key size.
     * 
     * @return The algorithm object.
     * 
     * @throws AlgorithmNotFoundException
     *             Throws in case of algorithm not found for the given name and key size.
     * @throws PKIConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    Algorithm getAlgorithmByNameAndKeySize(String algorithmName, Integer keySize) throws AlgorithmNotFoundException, PKIConfigurationServiceException;

    /**
     * Returns the list of algorithms based on algorithm name. For key generation type of of algorithms list contains more than one algorithm and for other types list contains only one algorithm.
     * 
     * @param name
     *            The algorithm name.
     * @return List of all algorithms.
     * 
     * @throws AlgorithmNotFoundException
     *             Throws in case of algorithm not found for the given name.
     * @throws PKIConfigurationServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions occurs while retrieving algorithms.
     */
    List<Algorithm> getAlgorithmsByName(String algorithmName) throws AlgorithmNotFoundException, PKIConfigurationServiceException;

    /**
     * Creation of EntityCategory. Returns the EntityCategory object.
     * 
     * @param entityCategory
     *            Object of EntityCategory with id or name set.
     * 
     * @return the EntityCategory object.
     * 
     * @throws EntityCategoryAlreadyExistsException
     *             Throws in case of category already exists.
     * 
     * @throws InvalidEntityCategoryException
     *             Throws in case of category format is invalid.
     * 
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     * 
     */
    EntityCategory createCategory(EntityCategory entityCategory) throws EntityCategoryAlreadyExistsException, InvalidEntityCategoryException, PKIConfigurationServiceException;

    /**
     * Allows updation of either categoryName or modifiable or both. Returns the EntityCategory object.
     * 
     * @param entityCategory
     *            Object of EntityCategory with updated values.
     * 
     * @return the EntityCategory object.
     * 
     * @throws EntityCategoryAlreadyExistsException
     *             thrown when category already exists with given updated name.
     * 
     * @throws InvalidEntityCategoryException
     *             Throws in case of category format is invalid
     * 
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     * 
     */
    EntityCategory updateCategory(EntityCategory entityCategory) throws EntityCategoryAlreadyExistsException, InvalidEntityCategoryException, PKIConfigurationServiceException;

    /**
     * Returns the entity category object based on entity category name.
     * 
     * @param entityCategory
     *            Object of EntityCategory with id or name set.
     * 
     * @return the EntityCategory object.
     * 
     * @throws EntityCategoryNotFoundException
     *             Throws in case of category not found with the given name.
     * 
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     * 
     */
    EntityCategory getCategory(EntityCategory entityCategory) throws EntityCategoryNotFoundException, PKIConfigurationServiceException;

    /**
     * Deletion of EntityCategory by name.
     * 
     * @param entityCategory
     *            Object of EntityCategory with id or name set.
     * 
     * @return void
     * 
     * @throws EntityCategoryNotFoundException
     *             Throws in case of category not found with the given name.
     * 
     * @throws EntityCategoryInUseException
     *             Throws in case of category is mapped to an entity/entity profile.
     * 
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    void deleteCategory(EntityCategory entityCategory) throws EntityCategoryNotFoundException, EntityCategoryInUseException, PKIConfigurationServiceException;

    /**
     * Check whether category name is available.
     * 
     * @param categoryName
     *            CategoryName to be verified for the availability.
     * @return true if name is available or else false.
     * 
     * @throws EntityCategoryNotFoundException
     *             Throws in case of category not found with the given input.
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    boolean isCategoryNameAvailable(String categoryName) throws EntityCategoryNotFoundException, PKIConfigurationServiceException;

    /**
     * Return the list of all entity categories in the database.
     * 
     * @return List of entity categories.
     * @throws PKIConfigurationServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    List<EntityCategory> listAllEntityCategories() throws PKIConfigurationServiceException;
}