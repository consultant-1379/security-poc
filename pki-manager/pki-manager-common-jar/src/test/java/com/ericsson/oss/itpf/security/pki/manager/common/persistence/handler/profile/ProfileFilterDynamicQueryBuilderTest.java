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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;

/**
 * This class is to test the ProfileDetailsPersistenceHandler
 * 
 * @author tcsrimrav
 */
@RunWith(MockitoJUnitRunner.class)
public class ProfileFilterDynamicQueryBuilderTest {

    
    @InjectMocks
    ProfileFilterDynamicQueryBuilder profileFilterDynamicQueryBuilder;
    
    @Spy
    final Logger logger = LoggerFactory.getLogger(ProfileFilterDynamicQueryBuilder.class);
    
    @Test
    public void testbuildQuery(){
        final ProfilesFilter profilesFilter = getProfilesFilter();

        final List<ProfileType> types = new ArrayList<ProfileType>();

        types.add(ProfileType.ENTITY_PROFILE);
        types.add(ProfileType.TRUST_PROFILE);
        types.add(ProfileType.CERTIFICATE_PROFILE);

        profilesFilter.setType(types);
        
        StringBuilder dynamicQuery = new StringBuilder();
 
        Map<String, Object> parameters = profileFilterDynamicQueryBuilder.build(profilesFilter, dynamicQuery);
        assertNotNull(parameters);
        
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
