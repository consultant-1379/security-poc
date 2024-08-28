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
package com.ericsson.oss.itpf.security.pki.manager.common.utils;

import java.util.HashSet;
import java.util.Set;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;

/**
 * This class is used to map status in {@link EntitiesFilter} to {@link CAStatus/EntityStatus}
 * 
 * @author tcsgoma
 * 
 */
public class EntityStatusUtils {
    private EntityStatusUtils() {

    }

    /**
     * This method is used to map status in {@link EntitiesFilter} to {@link CAStatus/EntityStatus}. It Does the following operation:
     * 
     * <ul>
     * <li>Map status to appropriate statusID in CAStatus</li>
     * <li>Add this statusID to entityStatusList</li>
     * <li>return entityStatusList</li>
     * </ul>
     * 
     * @param entitiesFilter
     *            which contains status of the entity
     * 
     * @return entityStatusList List of integers i.e., statusID's
     * 
     */
    public static Set<Integer> getEntityStatusList(final EntitiesFilter entitiesFilter) {
        final Set<Integer> entityStatusList = new HashSet<Integer>();

        for (final EntityStatus entityStatus : entitiesFilter.getStatus()) {
            entityStatusList.add(entityStatus.getId());
        }

        return entityStatusList;
    }

    /**
     * This method is used to map status in {@link EntitiesFilter} to {@link CAStatus/EntityStatus}. It Does the following operation:
     * 
     * <ul>
     * <li>Map status to appropriate statusID in CAStatus</li>
     * <li>Add this statusID to entityStatusList</li>
     * <li>return entityStatusList</li>
     * </ul>
     * 
     * @param entitiesFilter
     *            which contains status of the entity
     * 
     * @return entityStatusList List of integers i.e., statusID's
     * 
     */
    public static Set<Integer> getCAEntityStatusList(final EntitiesFilter entitiesFilter) {
        final Set<Integer> caEntityStatusList = new HashSet<Integer>();

        if (entitiesFilter.getStatus().contains(EntityStatus.NEW)) {
            caEntityStatusList.add(CAStatus.NEW.getId());
        }
        if (entitiesFilter.getStatus().contains(EntityStatus.ACTIVE)) {
            caEntityStatusList.add(CAStatus.ACTIVE.getId());
        }
        if (entitiesFilter.getStatus().contains(EntityStatus.INACTIVE)) {
            caEntityStatusList.add(CAStatus.INACTIVE.getId());
        }
        if (entitiesFilter.getStatus().contains(EntityStatus.DELETED)) {
            caEntityStatusList.add(CAStatus.DELETED.getId());
        }

        return caEntityStatusList;
    }

}
