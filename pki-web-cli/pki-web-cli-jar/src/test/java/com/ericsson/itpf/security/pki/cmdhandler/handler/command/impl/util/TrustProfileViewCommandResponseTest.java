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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import static org.junit.Assert.*;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiNameValueCommandResponse;
import com.ericsson.oss.itpf.security.pki.manager.common.setupdata.ExtCASetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.setupdata.TrustProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

@RunWith(MockitoJUnitRunner.class)
public class TrustProfileViewCommandResponseTest {

    @Spy
    private Logger logger = LoggerFactory.getLogger(TrustProfileViewCommandResponse.class);
    @Mock
    CommandHandlerUtils commandHandlerUtils;
    @InjectMocks
    TrustProfileViewCommandResponse trustProfileViewCommandResponse;
    Profiles profiles;
    PkiNameValueCommandResponse pkiNameValueCommandResponse;

    /**
     * SetUp method for setting unit test dependency
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();
        final TrustProfile trustProfile = trustProfileSetUpData.getTrustProfileDataForEqual();
        final List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();
        trustProfiles.add(trustProfile);
    }

    @Test
    public void testBuildCommandResponseForEntityProfile() throws DatatypeConfigurationException {
        MockitoAnnotations.initMocks(trustProfileViewCommandResponse);
        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();
        final TrustProfile trustProfile = trustProfileSetUpData.getTrustProfileDataForEqual();
        trustProfile.getExternalCAs();
        pkiNameValueCommandResponse = trustProfileViewCommandResponse.buildCommandResponseForTrustProfile(trustProfile);
        assertNotNull(pkiNameValueCommandResponse);
    }

    @Test
    public void testBuildCommandResponseForEntityProfilewithEXCA() throws DatatypeConfigurationException, ParseException {
        MockitoAnnotations.initMocks(trustProfileViewCommandResponse);
        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();
        final TrustProfile trustProfile = trustProfileSetUpData.getTrustProfileDataForEqual();
        final ExtCASetUpData externalCASetupData = new ExtCASetUpData();
        final ExtCA externalCA = externalCASetupData.getExtCAForEqual();
        final List<ExtCA> externalCAList = new ArrayList<ExtCA>();
        externalCAList.add(externalCA);
        trustProfile.setExternalCAs(externalCAList);
        pkiNameValueCommandResponse = trustProfileViewCommandResponse.buildCommandResponseForTrustProfile(trustProfile);
        assertNotNull(pkiNameValueCommandResponse);
    }

}
