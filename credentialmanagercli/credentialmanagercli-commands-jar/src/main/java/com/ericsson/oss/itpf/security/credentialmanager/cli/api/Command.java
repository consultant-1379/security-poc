/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.api;

import java.util.List;

public interface Command {
    enum COMMAND_TYPE {
        INSTALL, HELP, LIST, CHECK, CHECK_CLI_CREDENTIALS, VERSION, TEST, DAILYRUN
    };

    int execute();

    COMMAND_TYPE getType();

    List<String> getValidArguments();

}
