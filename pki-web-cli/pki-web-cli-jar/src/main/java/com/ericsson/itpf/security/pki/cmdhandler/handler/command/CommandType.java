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

package com.ericsson.itpf.security.pki.cmdhandler.handler.command;

import java.lang.annotation.*;

import javax.inject.Qualifier;

import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;

/**
 * Annotation to associate a CommandHandler implementation to a PKICommandType
 * 
 * @author xsumnan on 29/03/2015.
 * 
 * @see com.ericsson.itpf.security.pki.command.CommandHandler
 */
@Qualifier
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE, ElementType.FIELD, ElementType.PARAMETER, ElementType.METHOD })
@Documented
public @interface CommandType {
    PkiCommandType value();
}
