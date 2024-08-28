/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.profiles.api;

import java.util.List;

import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCertificateProfile;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlEntityProfile;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlTrustProfile;

public interface ProfileConfigInformation {

    List<XmlTrustProfile> getTrustProfilesInfo();

    List<XmlEntityProfile> getEntityProfilesInfo();

    List<XmlCertificateProfile> getCertificateProfilesInfo();

    String getXmlFilePath();
}
