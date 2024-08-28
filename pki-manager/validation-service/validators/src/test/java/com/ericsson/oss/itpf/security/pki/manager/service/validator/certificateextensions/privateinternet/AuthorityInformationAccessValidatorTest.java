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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.privateinternet;

import static org.mockito.Mockito.verify;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessDescription;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessMethod;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityInformationAccess;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityInformationAccessExtension;

/**
 * Test class for {@link AuthorityInformationAccessValidator}
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthorityInformationAccessValidatorTest {
    @Mock
    private Logger logger;

    @InjectMocks
    private AuthorityInformationAccessValidator authorityInformationAccessValidator;

    List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();
    AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess();
    List<AccessDescription> accessDescriptions = new ArrayList<AccessDescription>();
    AccessDescription accessDescription = new AccessDescription();

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidate() {
        accessDescription.setAccessLocation("ldap://ldap.example.com/cn=Barbara%20Jensen,dc=example,dc=com?cn,mail,telephoneNumber");
        accessDescription.setAccessMethod(AccessMethod.CA_ISSUER);
        accessDescriptions.add(accessDescription);
        authorityInformationAccess.setAccessDescriptions(accessDescriptions);
        authorityInformationAccess.setCritical(false);
        certificateExtensionList.add(authorityInformationAccess);
        authorityInformationAccessValidator.validate(certificateExtensionList.get(0), true, "TestIssuer");
        verify(logger).debug("Validating AuthorityInformationAccess in CertificateProfile{}", certificateExtensionList.get(0));
    }

    /**
     * Method to test validate method in negative scenario. When critical is set to true in AuthorityInformationAccess
     */
    @Test(expected = InvalidAuthorityInformationAccessExtension.class)
    public void testValidateAuthorityInformationAccessWithCriticalTrue() {
        authorityInformationAccess.setCritical(true);
        certificateExtensionList.add(authorityInformationAccess);
        authorityInformationAccessValidator.validate(certificateExtensionList.get(0), true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When AccessMethod is set to null in AccessDescriptions
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateAccessDescriptionWithAccessMethodNull() {
        accessDescription.setAccessLocation("ldap://ldap.example.com/cn=Barbara%20Jensen,dc=example,dc=com?cn,mail,telephoneNumber");
        accessDescription.setAccessMethod(null);
        accessDescriptions.add(accessDescription);
        authorityInformationAccess.setAccessDescriptions(accessDescriptions);
        authorityInformationAccess.setCritical(false);
        certificateExtensionList.add(authorityInformationAccess);
        authorityInformationAccessValidator.validate(certificateExtensionList.get(0), true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario. When AccessMethod is set to invalid value in AccessDescriptions
     */
    @Test(expected = InvalidAuthorityInformationAccessExtension.class)
    public void testValidateAccessLocationWithInvalidAccessLocation() {
        accessDescription.setAccessLocation("dfgdf");
        accessDescription.setAccessMethod(AccessMethod.CA_ISSUER);
        accessDescriptions.add(accessDescription);
        authorityInformationAccess.setAccessDescriptions(accessDescriptions);
        authorityInformationAccess.setCritical(false);
        certificateExtensionList.add(authorityInformationAccess);
        authorityInformationAccessValidator.validate(certificateExtensionList.get(0), true, "TestIssuer");
    }

    /**
     * Method to test validate method in negative scenario.
     */
    @Test
    public void testValidateAuthorityInformationAccessWithoutAccessDescriptions() {
        authorityInformationAccess.setAccessDescriptions(null);
        certificateExtensionList.add(authorityInformationAccess);
        authorityInformationAccessValidator.validate(certificateExtensionList.get(0), true, "TestIssuer");
        verify(logger).debug("Validating AuthorityInformationAccess in CertificateProfile{}", certificateExtensionList.get(0));
    }

    /**
     * Method to test validate method in negative scenario.
     */
    @Test
    public void testValidateAuthorityInformationAccessWithAccessLocationNull() {
        accessDescription.setAccessLocation(null);
        accessDescription.setAccessMethod(AccessMethod.CA_ISSUER);
        accessDescriptions.add(accessDescription);
        authorityInformationAccess.setAccessDescriptions(accessDescriptions);
        authorityInformationAccess.setCritical(false);
        certificateExtensionList.add(authorityInformationAccess);
        authorityInformationAccessValidator.validate(certificateExtensionList.get(0), true, "TestIssuer");
        verify(logger).debug("Validating AuthorityInformationAccess in CertificateProfile{}", certificateExtensionList.get(0));
    }

    /**
     * Method to test validate method in negative scenario.
     */
    @Test
    public void testCertificateExtensionListAsNull() {
        final CertificateExtension certificateExtension = null;
        authorityInformationAccessValidator.validate(certificateExtension, true, "TestIssuer");
        verify(logger).debug("Validating AuthorityInformationAccess in CertificateProfile{}", certificateExtension);
    }
}
