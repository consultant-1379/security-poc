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
public class UpdateCRLParamsValidator implements PKIWebCLIValidator{

    /* UPDATE CRL by FILE */
    public static final String FILE_NAME = "filePath";

    /* UPDATE CRL by URL */
    public static final String URL = "url";
    public static final String CA_NAME = "name";



    protected static final Set<String> expectedUpdateCRLFileKeys = new HashSet<>();
    static {
        expectedUpdateCRLFileKeys.add(FILE_NAME);
        expectedUpdateCRLFileKeys.add(CA_NAME);
    }

    protected static final Set<String> expectedUpdateCRLUrlKeys = new HashSet<>();
    static {
        expectedUpdateCRLUrlKeys.add(URL);
        expectedUpdateCRLUrlKeys.add(CA_NAME);
    }

    @Inject
    private Logger logger;

    @Override
    public void validate(final PkiPropertyCommand command) throws PkiWebCliException {

        logger.debug("Starting UpdateCRLParamsValidator with command type: {}", command.getCommandType());

        String commandResult = command.getProperties().keySet().toString();

        if (!validateKeys(command, expectedUpdateCRLFileKeys)
                && !validateKeys(command, expectedUpdateCRLUrlKeys)) {

            logger.error("Got an unexpected extcaupdatecrl Parameters '{}' ", commandResult);
            throw new CommandSyntaxException();
        }
        logger.debug("Command validated");
    }

    /**
     * @param command
     */
    protected boolean validateKeys(final PkiPropertyCommand command, final Set<String> expectedKeys) {
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
        if (expectedKeys.contains("url") && (command.getProperties().get("filePath") == null)) {
            actualAttributeKeys.remove("filePath");
        }
        if (actualAttributeKeys.containsAll(expectedKeys)) {
            actualAttributeKeys.removeAll(expectedKeys);
            if (actualAttributeKeys.isEmpty()) {
                return true;
            }
        }
        return false;
    }

}
