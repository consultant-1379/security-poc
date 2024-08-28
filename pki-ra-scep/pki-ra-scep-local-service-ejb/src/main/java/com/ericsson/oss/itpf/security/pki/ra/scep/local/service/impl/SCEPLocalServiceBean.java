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
package com.ericsson.oss.itpf.security.pki.ra.scep.local.service.impl;

import javax.ejb.Stateless;
import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.scep.model.ScepResponse;
import com.ericsson.oss.itpf.security.pki.ra.scep.local.service.api.SCEPLocalService;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.PersistenceHandler;

/**
 * This class is used to update the SCEP response status(failure ,success, pending) in pkirascep db based on ScepResponse object
 * 
 * @author xchowja
 *
 */
@Stateless
public class SCEPLocalServiceBean implements SCEPLocalService {

    @Inject
    private PersistenceHandler persistenceHandler;

    @Override
    public void updateSCEPResponseStatus(final ScepResponse scepResponse) {
        persistenceHandler.updateSCEPResponseStatus(scepResponse);
    }

}
