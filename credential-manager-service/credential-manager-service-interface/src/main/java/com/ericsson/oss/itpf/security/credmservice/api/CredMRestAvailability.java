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
package com.ericsson.oss.itpf.security.credmservice.api;

import javax.ejb.Local;

/**
 * @author egiator This interface is used internally by the unsecure REST call service to gather information about the availability of the service.
 *
 */
@Local
public interface CredMRestAvailability {

    /**
     * retrieve the status of the REST availability.
     *
     * @param value
     */
    boolean isEnabled();

    /**
     * @param value
     */
    void setRestEnabled(boolean value);

}
