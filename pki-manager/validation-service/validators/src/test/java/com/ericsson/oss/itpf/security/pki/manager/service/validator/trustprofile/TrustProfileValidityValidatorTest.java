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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.TrustProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.ProfileValidityValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile.TrustProfileValidityValidator;

/**
 * Class to test TrustProfileValidityValidator
 */
@RunWith(MockitoJUnitRunner.class)
public class TrustProfileValidityValidatorTest {

    @InjectMocks
    TrustProfileValidityValidator trustProfileValidityValidator;

    @Mock
    ProfileValidityValidator profileValidityValidator;

    @Mock
    Logger logger;

    private TrustProfile trustProfileLatestDate;
    private TrustProfile trustProfileOldDate;
    private Date latestDate;
    private Date oldDate;

    /**
     * Method to fill test data into TrustProfile and TrustProfileData
     */
    @Before
    public void setup() {

        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();

        latestDate = new Date();
        trustProfileLatestDate = trustProfileSetUpData.getTrustProfile();
        trustProfileLatestDate.setProfileValidity(latestDate);

        oldDate = new Date(System.currentTimeMillis() - 3600 * 1000);
        trustProfileOldDate = trustProfileSetUpData.getTrustProfile();
        trustProfileOldDate.setProfileValidity(oldDate);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile.TrustProfileValidityValidator#validate(com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile)}.
     */
    @Test
    public void testValidate() {

        trustProfileValidityValidator.validate(trustProfileLatestDate);

        Mockito.verify(profileValidityValidator).validate(trustProfileLatestDate.getProfileValidity());

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils#validateProfileValidity(java.util.Date)}.
     */
    @Test(expected = InvalidProfileAttributeException.class)
    public void testValidateProfileValidityThrowsInvalidProfileAttributeException() {

        Mockito.doThrow(new InvalidProfileAttributeException()).when(profileValidityValidator).validate(trustProfileOldDate.getProfileValidity());

        trustProfileValidityValidator.validate(trustProfileOldDate);

        Mockito.verify(profileValidityValidator).validate(trustProfileLatestDate.getProfileValidity());

    }

}
