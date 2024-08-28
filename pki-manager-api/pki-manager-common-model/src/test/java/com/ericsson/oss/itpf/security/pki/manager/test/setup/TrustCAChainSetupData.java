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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import javax.xml.datatype.DatatypeConfigurationException;

import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

public class TrustCAChainSetupData {

    final private CAEntitySetUpData caEntitySetUpData;

    /**
	 * 
	 */
    public TrustCAChainSetupData() {
        caEntitySetUpData = new CAEntitySetUpData();
    }

    /**
     * Method that returns valid {@link TrustCAChain}
     * 
     * @return {@link TrustCAChain}
     * @throws DatatypeConfigurationException
     */
    public TrustCAChain getTrustCAChainForEqual() throws DatatypeConfigurationException {
        final TrustCAChain trustCAChain = new TrustCAChain();

        trustCAChain.setChainRequired(true);
        final CAEntity internalCA = caEntitySetUpData.getCAEntityForEqual();
        trustCAChain.setInternalCA(internalCA);

        return trustCAChain;
    }

    /**
     * Method that returns different {@link TrustCAChain} object
     * 
     * @return {@link TrustCAChain}
     * @throws DatatypeConfigurationException
     */
    public TrustCAChain getTrustCAChainForNotEqual() throws DatatypeConfigurationException {
        final TrustCAChain trustCAChain = new TrustCAChain();

        trustCAChain.setChainRequired(false);
        final CAEntity internalCA = caEntitySetUpData.getCAEntityForNotEqual();
        trustCAChain.setInternalCA(internalCA);

        return trustCAChain;
    }
}
