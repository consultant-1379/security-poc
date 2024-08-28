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
package com.ericsson.oss.itpf.security.pki.manager.common.data;

import java.util.*;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

public class TrustProfileSetUpData {

    public final static String NAME_PATH_IN_CA = "certificateAuthorityData.name";
    public final static String NAME_PATH = "name";

    final private TrustCAChainSetupData trustCAChainSetupData;

    private TrustProfile trustProfile;
    private TrustProfileData trustProfileData;

    private List<TrustProfile> trustProfileList;
    private List<TrustProfileData> trustProfileDataList;

    private Map<String, Object> input;
    private List<String> values;
    private List<TrustCAChain> trustCAChains;
    private Set<String> internalCANames;

    private List<EntityProfileData> entityProfileDatas;
    private Set<TrustCAChainData> trustCAChainDatas;
    private List<CAEntityData> internalCaEntityDatas;
    private List<CAEntityData> externalCAsList;

    /**
     * Method to provide dummy data for tests.
     */
    public TrustProfileSetUpData() {
        trustCAChainSetupData = new TrustCAChainSetupData();
        fillTrustProfile();
        fillTrustProfileData();
    }

    /**
     * @return the internalCAsList
     */
    public Set<TrustCAChainData> getTrustCAChainDatas() {
        return trustCAChainDatas;
    }

    /**
     * @return the internalCAsList
     */
    public List<CAEntityData> getInternalCaEntityDatas() {
        return internalCaEntityDatas;
    }

    /**
     * Method to fill dummy data into TrustProfile.
     */
    private void fillTrustProfile() {
        trustCAChains = trustCAChainSetupData.getTrustCAChains();

        internalCANames = new HashSet<String>();

        for (final TrustCAChain trustCAChain : trustCAChains) {
            internalCANames.add(trustCAChain.getInternalCA().getCertificateAuthority().getName());
        }

        trustProfile = new TrustProfile();

        trustProfile.setId(1);
        trustProfile.setName("TestProfile");
        trustProfile.setTrustCAChains(trustCAChains);
        trustProfile.setExternalCAs(fillExtCA());

        trustProfileList = new ArrayList<TrustProfile>();
        trustProfileList.add(trustProfile);

        input = new HashMap<String, Object>();
        input.put("id", 1);
        input.put("name", "TestProfile");

        values = new ArrayList<String>();
        values.add("profile1");
        values.add("profile2");
    }

    private List<ExtCA> fillExtCA() {
        final ExtCA extCA = new ExtCA();
        final CertificateAuthority certAuth = new CertificateAuthority();
        certAuth.setName("External CA 1");
        extCA.setCertificateAuthority(certAuth);
        final List<ExtCA> extCAs = new ArrayList<ExtCA>();
        extCAs.add(extCA);
        return extCAs;
    }

    /**
     * Method to fill dummy data to TrustProfileData.
     */
    private void fillTrustProfileData() {

        trustCAChainDatas = trustCAChainSetupData.getTrustCAChainDatas();
        internalCaEntityDatas = new ArrayList<CAEntityData>();
        for (final TrustCAChainData trustCAChainData : trustCAChainDatas) {
            internalCaEntityDatas.add(trustCAChainData.getCAEntity());
        }

        final Set<CAEntityData> externalCAs = new HashSet<CAEntityData>();
        externalCAs.add(createExternalCA(1, "External CA 1"));

        externalCAsList = new ArrayList<CAEntityData>();
        externalCAsList.addAll(externalCAs);

        trustProfileData = new TrustProfileData();
        trustProfileData.setId(1);
        trustProfileData.setName("TestProfile");
        trustProfileData.setTrustCAChains(trustCAChainDatas);
        trustProfileData.setExternalCAs(externalCAs);

        final EntityProfileData entityProfileData = new EntityProfileData();
        entityProfileData.setId(1);
        entityProfileData.setName("entityprofile");

        entityProfileDatas = new ArrayList<EntityProfileData>();
        entityProfileDatas.add(entityProfileData);

        trustProfileDataList = new ArrayList<TrustProfileData>();
        trustProfileDataList.add(trustProfileData);

    }

    @SuppressWarnings("unused")
    private CAEntityData createInternalCA(final long id, final String name) {

        final CAEntityData internalCA = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        internalCA.setId(id);
        certificateAuthorityData.setName(name);
        internalCA.setCertificateAuthorityData(certificateAuthorityData);
        internalCA.setExternalCA(false);

        return internalCA;
    }

    private CAEntityData createExternalCA(final long id, final String name) {

        final CAEntityData externalCA = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        externalCA.setId(id);
        certificateAuthorityData.setName(name);
        externalCA.setCertificateAuthorityData(certificateAuthorityData);
        externalCA.setExternalCA(true);

        return externalCA;
    }

    /**
     * @return the internalCANames
     */
    public Set<String> getInternalCANames() {
        return internalCANames;
    }

    /**
     * @return the entityProfileDatas
     */
    public List<EntityProfileData> getEntityProfileDatas() {
        return entityProfileDatas;
    }

    /**
     * @return the trustProfile
     */
    public TrustProfile getTrustProfile() {
        return trustProfile;
    }

    /**
     * @return the trustProfileList
     */
    public List<TrustProfile> getTrustProfileList() {
        return trustProfileList;
    }

    /**
     * @return the trustProfileDataList
     */
    public List<TrustProfileData> getTrustProfileDataList() {
        return trustProfileDataList;
    }

    /**
     * @return the trustProfileData
     */
    public TrustProfileData getTrustProfileData() {
        return trustProfileData;
    }

    /**
     * @return the caEntities
     */
    public List<TrustCAChain> getTrustCAChains() {
        return trustCAChains;
    }

    /**
     * @return the input
     */
    public Map<String, Object> getInput() {
        return input;
    }

    /**
     * @return the values
     */
    public List<String> getValues() {
        return values;
    }

}
