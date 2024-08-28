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
package com.ericsson.oss.itpf.security.pki.ra.scep.processor;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.PersistenceHandler;

/**
 * This class fetches the corresponding days value from scepConfigurationListener and cleans the Database records which are older than the configured days
 * 
 * @author xhempal
 */
public class DBCleanUpProcessor {
    @Inject
    PersistenceHandler persistanceHandler;

    @Inject
    ConfigurationListener configurationListener;

    @Inject
    Logger logger;

    /**
     * This method invokes the database and and deletes the records in the database that are older than the days which are configurable.
     */
    public void cleanUpOldRecordsFromSCEPDB(final int recordPurgePeriod) {
        persistanceHandler.deleteOldRecordsFromScepDb(recordPurgePeriod);
    }

}
