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
package com.ericsson.oss.itpf.security.kaps.common.persistence;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import com.ericsson.oss.itpf.security.pki.common.persistence.AbstractPersistenceManager;

/**
 * This class returns entity manager corresponding to 'KAPSEXTERNALDS' persistent unit
 */
public class KAPSExternalPersistenceManager extends AbstractPersistenceManager {

    @PersistenceContext(unitName = "KAPSEXTERNALDS")
    private EntityManager entityManager;

    /**
     * @param entityManager
     */
    @Override
    public EntityManager getEntityManager() {
        return entityManager;
    }
}
