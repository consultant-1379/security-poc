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
package com.ericsson.oss.itpf.security.pki.ra.tdps.service.ejb;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.tdps.api.TrustDistributionParameters;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.TrustDistributionPointService;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionResourceNotFoundException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.impl.TDPSManager;

/**
 * This is a Stateless bean which retrieves certificate from DB and sends it to Rest resource.
 * 
 * @author tcsdemi
 *
 */
@Stateless
public class TrustDistributionPointServiceBean implements TrustDistributionPointService {

    @Inject
    TDPSManager tdpsManager;

    @Inject
    Logger logger;

    @Override
    public byte[] getCertificate(final TrustDistributionParameters trustDistributionParameters) throws TrustDistributionResourceNotFoundException, TrustDistributionServiceException {
        final String trustDistributeValue = trustDistributionParameters.toString();
        logger.info("Trust Distribution Point service to handle certificate request {} ", trustDistributeValue);

        return tdpsManager.getCertificate(trustDistributionParameters);

    }

}
