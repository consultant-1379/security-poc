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
package com.ericsson.oss.itpf.security.credmservice.ejb.startup;

import javax.annotation.PostConstruct;
import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.Singleton;
import javax.ejb.Startup;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.api.CredMRestAvailability;

@Singleton
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class CredMServiceStartupConfBean implements CredMRestAvailability {

    private static final Logger log = LoggerFactory.getLogger(CredMServiceStartupConfBean.class);

    volatile boolean flagEnable;

    /**
     * Starts the CredM Service startup procedure If the certificate for the jboss itself is not valid start a single action timeout that handles the
     * CredM Service initialization procedure
     */
    @PostConstruct
    public void credmServiceStartupProcedure() {

        log.info("CredM starting...");
    }

    @Override
    public void setRestEnabled(final boolean value) {
        this.flagEnable = value;
        log.info("REST interface availability set to " + value);
    }

    @Override
    public boolean isEnabled() {
        return this.flagEnable;
    }

}
