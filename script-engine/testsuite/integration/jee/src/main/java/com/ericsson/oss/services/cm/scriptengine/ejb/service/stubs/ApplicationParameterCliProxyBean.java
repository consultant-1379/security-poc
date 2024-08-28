/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.scriptengine.ejb.service.stubs;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.services.scriptengine.spi.CommandHandler;

@ApplicationScoped
public class ApplicationParameterCliProxyBean implements ApplicationParameterCliProxy {

	@EServiceRef(qualifier = "admin")
	protected CommandHandler applicationParameterCli;

	@Override
	public CommandHandler getApplicationParameterCli() {
		return applicationParameterCli;
	}
}