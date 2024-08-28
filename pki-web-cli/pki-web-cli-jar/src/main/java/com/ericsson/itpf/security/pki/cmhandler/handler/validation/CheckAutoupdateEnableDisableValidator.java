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
package com.ericsson.itpf.security.pki.cmhandler.handler.validation;

import java.util.Map;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;

public class CheckAutoupdateEnableDisableValidator implements PKIWebCLIValidator {

    private static final String AUTOUPDATE = "autoupdate";

    private static final String ENABLE = "enable";
    private static final String DISABLE = "disable";

    @Inject
    private Logger logger;

    @Override
    public void validate(final PkiPropertyCommand command)
            throws PkiWebCliException {

        logger.debug("Starting CheckAutoupdateEnableDisableValidator with command type: {}", command.getCommandType());

        final Map<String, Object> properties = command.getProperties();
        if (properties.containsKey(AUTOUPDATE)) {
            final String action = (String) properties.get(AUTOUPDATE);
            if (!(action.equals(ENABLE) || action.equals(DISABLE))) {
                logger.error("Got an unexpected action '{}' expecting " + ENABLE + " or " + DISABLE, action);
                throw new CommandSyntaxException();
            }
        }
        logger.debug("Command validated");
    }
}
