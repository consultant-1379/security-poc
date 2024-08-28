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
package com.ericsson.oss.itpf.security.credmservice.profiles.impl;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCertificateProfile;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlEntityProfile;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlTrustProfile;

public class SpecificProfilesLists {
    private final List<XmlTrustProfile> trustProfilesList = new ArrayList<XmlTrustProfile>();
    private final List<XmlCertificateProfile> certificateProfilesList = new ArrayList<XmlCertificateProfile>();
    private final List<XmlEntityProfile> entityProfilesList = new ArrayList<XmlEntityProfile>();

    public void splitIntoSpecificLists(final List<AppProfileXmlConfiguration> xmlProfiles) {

        if (xmlProfiles != null && !xmlProfiles.isEmpty()) {

            for (final AppProfileXmlConfiguration appProfile : xmlProfiles) {

                final List<XmlTrustProfile> xmlTrustProfileItem = appProfile.getTrustProfilesInfo();
                if (xmlTrustProfileItem != null && !xmlTrustProfileItem.isEmpty()) {
                    trustProfilesList.addAll(xmlTrustProfileItem);
                }

                final List<XmlCertificateProfile> xmlCertificateProfileItem = appProfile.getCertificateProfilesInfo();
                if (xmlCertificateProfileItem != null && !xmlCertificateProfileItem.isEmpty()) {
                    certificateProfilesList.addAll(xmlCertificateProfileItem);
                }

                final List<XmlEntityProfile> xmlEntityProfileItem = appProfile.getEntityProfilesInfo();
                if (xmlEntityProfileItem != null && !xmlEntityProfileItem.isEmpty()) {
                    entityProfilesList.addAll(xmlEntityProfileItem);
                }

            }
        }
    }

    /**
     * @return the trustProfilesList
     */
    public List<XmlTrustProfile> getTrustProfilesList() {
        return trustProfilesList;
    }

    /**
     * @return the certificateProfilesList
     */
    public List<XmlCertificateProfile> getCertificateProfilesList() {
        return certificateProfilesList;
    }

    /**
     * @return the entityProfilesList
     */
    public List<XmlEntityProfile> getEntityProfilesList() {
        return entityProfilesList;
    }

}
