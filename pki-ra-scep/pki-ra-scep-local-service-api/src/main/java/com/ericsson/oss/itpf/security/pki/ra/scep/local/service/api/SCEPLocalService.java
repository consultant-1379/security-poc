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
package com.ericsson.oss.itpf.security.pki.ra.scep.local.service.api;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.scep.model.ScepResponse;

/**
 * This interface is used to update the SCEP response status(failure ,success, pending) in pkirascep db based on ScepResponse object
 * 
 * @author xchowja
 *
 */
@EService
@Local
public interface SCEPLocalService {
    /**
     * This method is used to update the SCEP response status(failure ,success, pending) in pkirascep db based on ScepResponse object
     * 
     * @param scepResponse
     */
    void updateSCEPResponseStatus(final ScepResponse scepResponse);
}
