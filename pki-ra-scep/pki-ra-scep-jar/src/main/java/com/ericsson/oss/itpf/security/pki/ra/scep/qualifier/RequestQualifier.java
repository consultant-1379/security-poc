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
package com.ericsson.oss.itpf.security.pki.ra.scep.qualifier;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.*;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import javax.inject.Qualifier;

import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Operation;

/**
 * This @interface will be used to provide instance of a particular class based on SCEP operation.
 *
 * @author xkarlak
 */
@Qualifier
@Retention(RUNTIME)
@Target({ FIELD, TYPE, METHOD, PARAMETER })
public @interface RequestQualifier {
    Operation value();
}
