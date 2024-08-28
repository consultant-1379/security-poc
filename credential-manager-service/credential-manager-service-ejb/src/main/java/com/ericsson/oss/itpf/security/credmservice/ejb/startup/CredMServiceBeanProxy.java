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

import javax.ejb.Local;

import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerCheckException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerDbUpgradeException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerStartupException;

/**
 * This is the interface of a proxy bean used to decouple timer handlers from the execution of a task. This bean will be injected into the timer handlers via @EJB annotation to make a new transaction
 * start. A fail in a task execution causes the rollback of the entire new transaction, but not the timer.
 */
@Local
public interface CredMServiceBeanProxy {

    void pkiDbUpgrade() throws CredentialManagerDbUpgradeException;
	
    void generateJBossCredentials() throws CredentialManagerStartupException;

    void checkJBossCredentials() throws CredentialManagerCheckException;

	void checkDbCvnStatus();

}
