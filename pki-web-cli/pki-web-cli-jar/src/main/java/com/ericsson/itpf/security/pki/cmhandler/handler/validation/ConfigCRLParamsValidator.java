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

import java.util.HashSet;
import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;


/**
 *
 * @author DespicableUs
 */
public class ConfigCRLParamsValidator implements PKIWebCLIValidator{

    public static final String AUTO_UPDATE = "autoupdate";

    public static final String TIMER = "timer";

    public static final String CA_NAME = "name";

    private static final String DISABLE = "disable";

    protected static final Set<String> expectedConfigCRLKeys = new HashSet<>();
    static {
        expectedConfigCRLKeys.add(AUTO_UPDATE);
        expectedConfigCRLKeys.add(CA_NAME);
    }


    protected static final Set<String> optionalConfigCRLKeys = new HashSet<>();
    static {
        optionalConfigCRLKeys.add(TIMER);
    }

    @Inject
    private Logger logger;

    @Override
    public void validate(final PkiPropertyCommand command) throws PkiWebCliException {

        logger.debug("Starting ConfigCRLParamsValidator with command type: {}", command.getCommandType());

        String commandResult = command.getProperties().keySet().toString();

        if (!validateKeys(command, expectedConfigCRLKeys, optionalConfigCRLKeys)) {
            logger.error("Got an unexpected extcaconfigcrl Parameters '{}' ", commandResult);
            throw new CommandSyntaxException();
        }

        command.getProperties().get(TIMER);
        if (command.getProperties().get(AUTO_UPDATE) == DISABLE && command.getProperties().get(TIMER) != null) {
            logger.error("Autoupdate value 'disable' doesn't support timer parameter '{}' ", commandResult);
            throw new CommandSyntaxException();
        }
        logger.debug("Command validated");
    }

    /**
     * @param command
     */
    protected boolean validateKeys(final PkiPropertyCommand command, final Set<String> expectedKeys, final Set<String> optionalKeys) {
        final Set<String> actualAttributeKeys = new HashSet<>(command.getProperties().keySet());
        if (actualAttributeKeys.contains("command")) {
            actualAttributeKeys.remove("command");
        }
        if (actualAttributeKeys.contains("filename")) {
            actualAttributeKeys.remove("filename");
        }
        if (actualAttributeKeys.contains("fileName")) {
            actualAttributeKeys.remove("fileName");
        }
        if (actualAttributeKeys.contains("filePath")) {
            actualAttributeKeys.remove("filePath");
        }
        if (actualAttributeKeys.containsAll(expectedKeys)) {
            actualAttributeKeys.removeAll(expectedKeys);
            if (actualAttributeKeys.isEmpty() || optionalKeys.containsAll(actualAttributeKeys)) {
                return true;
            }
        }
        return false;
    }

}
