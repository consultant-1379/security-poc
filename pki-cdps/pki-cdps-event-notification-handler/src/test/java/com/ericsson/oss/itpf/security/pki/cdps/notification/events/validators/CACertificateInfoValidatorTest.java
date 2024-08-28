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
package com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators;

import static org.mockito.Mockito.times;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CACertificateInfoValidator;
import com.ericsson.oss.itpf.security.pki.cdps.notification.setup.SetUpData;

/**
 * This class used to test CACertificateInfoValidator functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CACertificateInfoValidatorTest extends SetUpData {

    @InjectMocks
    CACertificateInfoValidator caCertificateInfoValidator;

    @Mock
    CACertificateInfo caCertificateInfoMock;

    @Mock
    private SystemRecorder systemRecorder;

    private CACertificateInfo caCertificateInfo;
    private List<CACertificateInfo> caCertificateInfos;
    private List<CACertificateInfo> caCertificateInfosEmpty;
    private CACertificateInfo caCertificateInfoEmpty;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        caCertificateInfo = prepareCACertificateInfo();

        caCertificateInfos = prepareCACertificateInfoList();

        caCertificateInfoEmpty = prepareCACertInfoEmpty();
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CACertificateInfoValidator#validate(java.util.List)}.
     */
    @Test
    public void testValidate() {

        caCertificateInfoValidator.validate(caCertificateInfos);

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CACertificateInfoValidator#validate(java.util.List)}.
     */
    @Test(expected = CRLValidationException.class)
    public void testValidateListOfCACertificateInfoThrowsCRLValidationException() {

        caCertificateInfoValidator.validate(caCertificateInfosEmpty);

        Mockito.verify(caCertificateInfo, times(1)).getCaName();
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CACertificateInfoValidator#validate(com.ericsson.oss.itpf.security.pki.ra.cdps.cdt.CACertificateInfo)}.
     */
    @Test
    public void testValidateCACertificateInfo() {

        caCertificateInfoValidator.validate(caCertificateInfo);

    }

    @Test(expected = CRLValidationException.class)
    public void testValidateCACertificateInfoThrowsCRLValidationException() {

        caCertificateInfoValidator.validate(caCertificateInfoEmpty);

    }

}
