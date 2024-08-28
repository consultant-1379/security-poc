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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data;

import java.util.*;

import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustCAChainData;

/**
 * This class is used to prepare trust profile setup data.
 */
public class TrustCAChainSetupData {

    private EntitiesSetUpData entitiesSetUpData;

    private TrustCAChain trustCAChain;
    private List<TrustCAChain> trustCAChains;
    private TrustCAChainData trustCAChainData;
    private Set<TrustCAChainData> trustCAChainDatas;

    /**
	 * 
	 */
    public TrustCAChainSetupData() {
        entitiesSetUpData = new EntitiesSetUpData();
        fillTrustCAChain();
        fillTrustCAChainData();
    }

    private void fillTrustCAChain() {
        trustCAChain = new TrustCAChain();
        trustCAChain.setChainRequired(true);

        CAEntity internalCA = entitiesSetUpData.getCaEntity();
        trustCAChain.setInternalCA(internalCA);

        trustCAChains = new ArrayList<TrustCAChain>();
        trustCAChains.add(trustCAChain);
    }

    private void fillTrustCAChainData() {
        trustCAChainData = new TrustCAChainData();

        CAEntityData caEntityData = entitiesSetUpData.getCaEntityData();

        trustCAChainData.setChainRequired(true);
        trustCAChainData.setCAEntity(caEntityData);

        trustCAChainDatas = new HashSet<TrustCAChainData>();
        trustCAChainDatas.add(trustCAChainData);
    }

    /**
     * @return the trustCAChain
     */
    public TrustCAChain getTrustCAChain() {
        return trustCAChain;
    }

    /**
     * @return the trustCAChains
     */
    public List<TrustCAChain> getTrustCAChains() {
        return trustCAChains;
    }

    /**
     * @return the trustCAChainData
     */
    public TrustCAChainData getTrustCAChainData() {
        return trustCAChainData;
    }

    /**
     * @return the trustCAChainDatas
     */
    public Set<TrustCAChainData> getTrustCAChainDatas() {
        return trustCAChainDatas;
    }

}
