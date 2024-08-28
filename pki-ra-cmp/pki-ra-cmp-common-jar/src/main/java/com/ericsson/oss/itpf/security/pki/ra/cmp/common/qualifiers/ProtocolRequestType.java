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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.qualifiers;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import javax.inject.Qualifier;

/**
 * @author tcsdemi
 *         <p>
 *         This is a qualifier for RequestType, it has a value based on each requestType as below:<br>
 *         1. If request is Initialization request then qualifier will have a value of Constants.TYPE_INIT_REQ.<br>
 *         2. If request is Key Update request then qualifier will have value of Constants.TYPE_KEY_UPDATE_REQ.<br>
 *         3. If request is Poll request then qualifier will have value of Constants.TYPE_POLL_REQ.<br>
 *         4. If request is Certificate confirmation request then qualifier will have value of Constants.TYPE_CERT_CONF.<br>
 * 
 *         In case of any new request types to be supported by CMP application then a corresponding RequestHandler will have a qualifier mentiond as: <code><pre>
 * @ProtocolRequestType(Constants.TYPE_NEW_REQUEST)<br> public class <New_Request_type>RequestHandler implements RequestHandler {<br> }
 * 
 * 
 *
 */
@Qualifier
@Retention(RUNTIME)
@Target({ FIELD, TYPE, METHOD })
public @interface ProtocolRequestType {
    int value();

}
