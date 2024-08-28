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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;

@Entity
@Table(name = "TrustProfile")
public class TrustProfileData extends AbstractProfileData implements Serializable {

    private static final long serialVersionUID = -2029154331915669224L;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "trustChainId.trustProfileData", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<TrustCAChainData> trustCAChains = new HashSet<TrustCAChainData>();

    // BEGIN dDU-TORF-47941 - DESPICABLE_US
    @ManyToMany(fetch = FetchType.EAGER, cascade = { CascadeType.REFRESH })
    @JoinTable(name = "TRUSTPROFILE_EXTERNALCA", joinColumns = @JoinColumn(name = "trust_profile_id"), inverseJoinColumns = @JoinColumn(name = "externalca_id"))
    private Set<CAEntityData> externalCAs = new HashSet<CAEntityData>();

    // END dDU-TORF-47941 - DESPICABLE_US

    /**
     * @return the internalCAs
     */
    public Set<TrustCAChainData> getTrustCAChains() {
        return trustCAChains;
    }

    /**
     * @param internalCAs
     *            the internalCAs to set
     */
    public void setTrustCAChains(final Set<TrustCAChainData> trustCAChains) {
        this.trustCAChains = trustCAChains;
    }

    /**
     * @return the externalCAs
     */
    public Set<CAEntityData> getExternalCAs() {
        return externalCAs;
    }

    /**
     * @param externalCAs
     *            the externalCAs to set
     */
    public void setExternalCAs(final Set<CAEntityData> externalCAs) {
        this.externalCAs = externalCAs;
    }

}
