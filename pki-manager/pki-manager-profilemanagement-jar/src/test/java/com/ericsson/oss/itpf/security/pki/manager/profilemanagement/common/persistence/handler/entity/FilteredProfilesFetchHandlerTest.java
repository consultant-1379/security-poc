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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.persistence.handler.entity;

import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.util.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.ProfileModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfileFilterDynamicQueryBuilder;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;

/**
 * This class is to test the ProfileDetailsPersistenceHandler
 * 
 * @author tcsrimrav
 */
@RunWith(MockitoJUnitRunner.class)
public class FilteredProfilesFetchHandlerTest {

    @InjectMocks
    FilteredProfilesFetchHandler filteredProfilesFetchHandler;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    ProfileModelMapperFactory profileModelMapperFactory;

    @Spy
    final Logger logger = LoggerFactory.getLogger(FilteredProfilesFetchHandlerTest.class);

    @Mock
    ProfileFilterDynamicQueryBuilder profileFilterDynamicQueryBuilder;

    @Test
    public void testgetProfileDetails() {

        final ProfilesFilter profilesFilter = getProfilesFilter();

        final List<ProfileType> types = new ArrayList<ProfileType>();

        types.add(ProfileType.ENTITY_PROFILE);
        types.add(ProfileType.TRUST_PROFILE);
        types.add(ProfileType.CERTIFICATE_PROFILE);

        profilesFilter.setType(types);

        final List<Object> profileDetails = new ArrayList<Object>();

        Object[] profileDetailRow = new Object[5];
        profileDetailRow[4] = "CERTIFICATE_PROFILE";
        profileDetailRow[0] = BigInteger.valueOf(1L);
        profileDetailRow[1] = "TestName";
        profileDetailRow[2] = new Boolean(true);

        profileDetails.add(profileDetailRow);

        final StringBuilder dynamicQuery = new StringBuilder();

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("Name", profilesFilter.getName());
        attributes.put("status_active", profilesFilter.getStatus().isActive());
        attributes.put("status_inactive", profilesFilter.getStatus().isInactive());

        Mockito.when(profileFilterDynamicQueryBuilder.build(profilesFilter, dynamicQuery)).thenReturn(attributes);

        Mockito.when(persistenceManager.findEntitiesByNativeQuery(Mockito.anyString(), Mockito.anyMapOf(String.class, Object.class), Mockito.anyInt(), Mockito.anyInt())).thenReturn(profileDetails);

        final List<AbstractProfile> expedtedProfilesList = filteredProfilesFetchHandler.getProfileDetails(profilesFilter);

        assertNotNull(expedtedProfilesList);
    }

    @Test
    public void testgetProfileDetails_EntiyProfile() {

        final ProfilesFilter profilesFilter = getProfilesFilter();

        final List<ProfileType> types = new ArrayList<ProfileType>();

        types.add(ProfileType.ENTITY_PROFILE);
        types.add(ProfileType.TRUST_PROFILE);
        types.add(ProfileType.CERTIFICATE_PROFILE);

        profilesFilter.setType(types);

        final List<Object> profileDetails = new ArrayList<Object>();

        Object[] profileDetailRow = new Object[5];
        profileDetailRow[4] = "ENTITY_PROFILE";
        profileDetailRow[0] = BigInteger.valueOf(1L);
        profileDetailRow[1] = "TestName";
        profileDetailRow[2] = new Boolean(true);

        profileDetails.add(profileDetailRow);

        final StringBuilder dynamicQuery = new StringBuilder();

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("Name", profilesFilter.getName());
        attributes.put("status_active", profilesFilter.getStatus().isActive());
        attributes.put("status_inactive", profilesFilter.getStatus().isInactive());

        Mockito.when(profileFilterDynamicQueryBuilder.build(profilesFilter, dynamicQuery)).thenReturn(attributes);

        Mockito.when(persistenceManager.findEntitiesByNativeQuery(Mockito.anyString(), Mockito.anyMapOf(String.class, Object.class), Mockito.anyInt(), Mockito.anyInt())).thenReturn(profileDetails);

        final List<AbstractProfile> expedtedProfilesList = filteredProfilesFetchHandler.getProfileDetails(profilesFilter);

        assertNotNull(expedtedProfilesList);
    }

    @Test
    public void testgetProfileDetails_TrustProfile() {

        final ProfilesFilter profilesFilter = getProfilesFilter();

        final List<ProfileType> types = new ArrayList<ProfileType>();

        types.add(ProfileType.ENTITY_PROFILE);
        types.add(ProfileType.TRUST_PROFILE);
        types.add(ProfileType.CERTIFICATE_PROFILE);

        profilesFilter.setType(types);

        final List<Object> profileDetails = new ArrayList<Object>();

        Object[] profileDetailRow = new Object[5];
        profileDetailRow[4] = "TRUST_PROFILE";
        profileDetailRow[0] = BigInteger.valueOf(1L);
        profileDetailRow[1] = "TestName";
        profileDetailRow[2] = new Boolean(true);

        profileDetails.add(profileDetailRow);

        final StringBuilder dynamicQuery = new StringBuilder();

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("Name", profilesFilter.getName());
        attributes.put("status_active", profilesFilter.getStatus().isActive());
        attributes.put("status_inactive", profilesFilter.getStatus().isInactive());

        Mockito.when(profileFilterDynamicQueryBuilder.build(profilesFilter, dynamicQuery)).thenReturn(attributes);

        Mockito.when(persistenceManager.findEntitiesByNativeQuery(Mockito.anyString(), Mockito.anyMapOf(String.class, Object.class), Mockito.anyInt(), Mockito.anyInt())).thenReturn(profileDetails);

        final List<AbstractProfile> expedtedProfilesList = filteredProfilesFetchHandler.getProfileDetails(profilesFilter);

        assertNotNull(expedtedProfilesList);
    }

    /**
     * Test Data SetUP for ProfileFilterDTO.
     */
    private ProfilesFilter getProfilesFilter() {

        final ProfilesFilter profilesFilter = new ProfilesFilter();

        profilesFilter.setLimit(10);
        profilesFilter.setOffset(1);
        profilesFilter.setName("Test%");

        final com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfileStatusFilter status = new com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfileStatusFilter();
        status.setActive(true);
        status.setInactive(true);

        profilesFilter.setStatus(status);

        final List<ProfileType> types = new ArrayList<ProfileType>();

        types.add(ProfileType.CERTIFICATE_PROFILE);

        profilesFilter.setType(types);

        return profilesFilter;
    }
}
