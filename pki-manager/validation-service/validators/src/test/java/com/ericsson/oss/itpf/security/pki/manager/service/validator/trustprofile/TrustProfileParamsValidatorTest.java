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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.TrustProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile.TrustProfileParamsValidator;

/**
 * Class to test TrustProfileParamsValidator
 */
@RunWith(MockitoJUnitRunner.class)
public class TrustProfileParamsValidatorTest {

    @InjectMocks
    TrustProfileParamsValidator trustProfileParamsValidator;

    @Mock
    Logger logger;

    private TrustProfile trustProfile;

    /**
     * Method to fill the data into CAEntity
     */
    @Before
    public void setup() {

        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();
        trustProfile = trustProfileSetUpData.getTrustProfile();
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile.TrustProfileParamsValidator#validate(com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile)}.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateThrowsMissingMandatoryFieldException() {

        trustProfileParamsValidator.validate(new TrustProfile());

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile.TrustProfileParamsValidator#validate(com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile)}.
     */
    @Test
    public void testValidate() {

        trustProfileParamsValidator.validate(trustProfile);

    }
}
