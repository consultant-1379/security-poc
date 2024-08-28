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

package com.ericsson.oss.itpf.security.pki.ra.cmp.service.scheduler;

import java.util.*;

import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;

/**
 * This class is for CMP database cleanup for entries whose modified date is older than the request timeout.
 *
 * @author tcsdemi
 *
 */

public class DBCleanUpHandler {

    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    ConfigurationParamsListener configurationParamsListener;

    @Inject
    Logger logger;

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void cleanUpDB() {

        updateRecordsWithWaitCertConf();
        deleteTimeOutRecords();
    }

    private void deleteTimeOutRecords() {
        try {
            final int timeOut = configurationParamsListener.getRequestTimeOut();
            logger.info("Cleaning up CMP database record from the timer service");
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.DATE, -timeOut);
            Date dateToCompare = cal.getTime();

            persistenceHandler.deleteRecordsByCreatedDate(dateToCompare);
        } catch (final Exception exception) {
            logger.error("Error occured while deleting Rows in Timer", exception);
        }
    }

    private void updateRecordsWithWaitCertConf(){
        try {
            logger.info("Updating records with WAIT_FOR_ACK to TO_BE_REVOKED_NEW from the timer service");
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.DATE, -1);
            Date dateToCompare = cal.getTime();

            persistenceHandler.updateRecordsStatusByCreatedDate(dateToCompare);
        } catch (final Exception exception) {
            logger.debug("Error occured while updating records status in DB in timer ", exception);
        }
    }
}
