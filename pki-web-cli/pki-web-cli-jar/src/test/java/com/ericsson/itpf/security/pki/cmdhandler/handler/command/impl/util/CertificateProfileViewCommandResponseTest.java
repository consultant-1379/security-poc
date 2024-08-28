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

import java.net.URL;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiNameValueCommandResponse;
import com.ericsson.oss.itpf.sdkutils.xml.JaxbUtil;
import com.ericsson.oss.itpf.security.pki.manager.common.setupdata.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;

@RunWith(MockitoJUnitRunner.class)
public class CertificateProfileViewCommandResponseTest {
    @Spy
    private Logger logger = LoggerFactory.getLogger(CertificateProfileViewCommandResponse.class);
    @Mock
    CommandHandlerUtils commandHandlerUtils;
    @InjectMocks
    CertificateProfileViewCommandResponse certificateProfileViewCommandResponse;

    Profiles profiles;

    private CertificateProfileSetUpData certificateProfileSetUpData;

    /**
     * SetUp method for setting unit test dependency
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        final URL url = getClass().getClassLoader().getResource("profiles.xml");
        profiles = JaxbUtil.getObject(url.openStream(), Profiles.class);
        certificateProfileSetUpData = new CertificateProfileSetUpData();
    }

    @Test
    public void testBuildCommandResponseForCertificateProfile() throws DatatypeConfigurationException {
        MockitoAnnotations.initMocks(certificateProfileViewCommandResponse);
        PkiNameValueCommandResponse pkiNameValueCommandResponse = null;
        pkiNameValueCommandResponse = certificateProfileViewCommandResponse.buildCommandResponseForCertificateProfile(certificateProfileSetUpData.getCertificateProfileForNotEqual());
        assertNotNull(pkiNameValueCommandResponse);
    }
}
