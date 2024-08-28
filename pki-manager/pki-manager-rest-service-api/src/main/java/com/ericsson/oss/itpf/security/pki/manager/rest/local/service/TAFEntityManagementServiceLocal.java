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
package com.ericsson.oss.itpf.security.pki.manager.rest.local.service;

import java.util.List;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;

/**
 * This interface is provided for handling the calls related to entity management 
 * from TAF
 * 
 * @author xlakdag
 * 
 */
@EService
@Local
public interface TAFEntityManagementServiceLocal {
    
    /**
     * To get pki manager CA Entity Names contains ca entity name
     * @param caentity_name
     * @return
     */
    List<String> getCAEntityNamesFrmPKIManager(final String caentity_name);
    
    
    /**
     * To get pki manager Entity Names contains entity name
     * @param entity_name
     * @return
     */
    List<String> getEndEntityNamesFrmPKIManager(final String entity_name);
    
    /**
     * To partition entity names list
     * @param caEntityNames
     * @return
     */
    List<List<String>> getPartitionedLists(final List<String> caEntityNames);
    
    /**
     * To delete PKI Manager CA Entity Data by Name
     * @param caEntityName
     */
    void deleteCAEntityDataFrmPKIManager(final String caEntityName);
    
    /**
     * To delete PKI Core End Entities based on entity name
     * @param entity_name
     */
    void deleteEndEntitiesFrmPKICore(final String entity_name);
    
    /**
     * To delete CA keys from kaps data base based on entity name
     * @param caentity_name
     */
    void deleteCaKeysFrmKaps(final String caentity_name);
    
    /**
     * To get TAF core CA Entities contains ca entity name
     * @param caentity_name
     * @return
     */
    List<String> getCAEntityNamesFromPKICore(final String caentity_name);
    
    /**
     * To delete PKI Core CA Entity Data By Name
     * @param caEntityNames
     */
    void deleteCAEntityDataFromPKICore(final String caEntityName);

    /**
     * To delete PKI Manager Entity Data by Name
     * @param entityName
     */
    void deleteEndEntityDataFrmPKIManager(String entityName);

    /**
     * To delete PKI Manager ExtCA Entity Data by Name
     * @param entityName
     */
    void deleteExtCAEndEntityDataFrmPKIManager(final String entityName);
}
