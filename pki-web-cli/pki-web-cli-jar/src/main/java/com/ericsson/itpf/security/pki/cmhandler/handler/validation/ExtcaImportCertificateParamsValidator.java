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
public class ExtcaImportCertificateParamsValidator implements PKIWebCLIValidator {

    /* UPDATE CRL by FILE */
    final public static String FILE_NAME = "filePath";

    final public static String CA_NAME = "name";

    final private static String CHAIN_REQUIRED = "chainrequired";

    private static final String RFC_VALIDATION = "rfcvalidation";

    protected static final Set<String> expectedImportCertificateKeys = new HashSet<>();
    static {
        expectedImportCertificateKeys.add(FILE_NAME);
        expectedImportCertificateKeys.add(CHAIN_REQUIRED);
    }

    protected static final Set<String> optionalImportCertificateKeys = new HashSet<>();
    static {
        optionalImportCertificateKeys.add(CA_NAME);
        optionalImportCertificateKeys.add(RFC_VALIDATION);
    }

    @Inject
    private Logger logger;

    @Override
    public void validate(final PkiPropertyCommand command) throws PkiWebCliException {

        logger.debug("Starting UpdateCRLParamsValidator with command type: {}", command.getCommandType());

        String commandResult = command.getProperties().keySet().toString();

        if (!validateKeys(command, expectedImportCertificateKeys, optionalImportCertificateKeys)) {

            logger.error("Got an unexpected Reissue Parameters '{}' ", commandResult);
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
        if (command.getProperties().get("filePath") == null) {
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
