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

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CRLInfoValidator;
import com.ericsson.oss.itpf.security.pki.cdps.notification.setup.SetUpData;

/**
 * This class used to test CRLInfoValidator functionality
 * 
 * @author tcsgoja
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CRLInfoValidatorTest extends SetUpData {

    @InjectMocks
    CRLInfoValidator crlInfoValidator;

    @Mock
    private SystemRecorder systemRecorder;

    private CRLInfo crlInfo;
    private CRLInfo crlInfoNull;
    private CRLInfo crlInfoEmpty;
    private List<CRLInfo> crlInfoList;
    private List<CRLInfo> crlInfoListEmpty;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        crlInfo = prepareCRLInfo();

        crlInfoList = prepareCRLInfoList();

        crlInfoNull = prepareCRLInfoEmpty();

        crlInfoEmpty = new CRLInfo();
        crlInfoEmpty.setCaCertificateInfo(prepareCACertInfoEmpty());
        crlInfoEmpty.setEncodedCRL(getX509CRL("src/test/resources/crls/testCA.crl"));
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CRLInfoValidator#validate(java.util.List)} .
     */
    @Test
    public void testValidateListOfCRLInfoThrowsCRLValidationException() {
        crlInfoValidator.validate(crlInfoList);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CRLInfoValidator#validate(java.util.List)} .
     */
    @Test(expected = CRLValidationException.class)
    public void testValidateListOfCRLInfo() {
        crlInfoValidator.validate(crlInfoListEmpty);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CRLInfoValidator#validate(com.ericsson.oss.itpf.security.pki.ra.cdps.cdt.CRLInfo)} .
     */
    @Test
    public void testValidateCRLInfo() {
        crlInfoValidator.validate(crlInfo);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CRLInfoValidator#validate(com.ericsson.oss.itpf.security.pki.ra.cdps.cdt.CRLInfo)} .
     */
    @Test(expected = CRLValidationException.class)
    public void testValidateCRLInfoThrowsCRLValidationException() {
        crlInfoValidator.validate(crlInfoNull);
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CRLInfoValidator#validate(com.ericsson.oss.itpf.security.pki.ra.cdps.cdt.CRLInfo)} .
     */
    @Test(expected = CRLValidationException.class)
    public void testValidateCRLInfoThrowsCRLValidationExceptionEmptyCAInfo() {
        crlInfoValidator.validate(crlInfoEmpty);
    }

}
