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

package com.ericsson.itpf.security.pki.cmdhandler.api.command;

import java.io.Serializable;

/**
 * Super interface for all PKICommands
 * 
 * @author xsumnan on 29/03/2015.
 */
public interface PkiCommand extends Serializable {

    /**
     * Root command context
     */
    public static final String APP_ID = "pkiadm";

}
