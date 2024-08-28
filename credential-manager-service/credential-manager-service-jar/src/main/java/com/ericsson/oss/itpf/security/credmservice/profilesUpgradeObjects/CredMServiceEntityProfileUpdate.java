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
package com.ericsson.oss.itpf.security.credmservice.profilesUpgradeObjects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.util.PkiObjectSelector;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

public class CredMServiceEntityProfileUpdate {

    private static final Logger log = LoggerFactory.getLogger(CredMServiceEntityProfileUpdate.class);

    public static EntityProfile updateCvn_2(final EntityProfile... entityProfiles) {

        final String SCEP_IPSEC = "SCEPRA_IPSec_EP";
        final String SCEP_OAM = "SCEPRA_OAM_EP";

        final EntityProfile xmlEntityProfile = entityProfiles[0];
        final EntityProfile pkiEntityProfile = (EntityProfile) PkiObjectSelector.getPkiObject(entityProfiles);

        if (pkiEntityProfile == null) {
            return null;
        }

        if (xmlEntityProfile.getName().equals(SCEP_IPSEC) || xmlEntityProfile.getName().equals(SCEP_OAM)) {

            log.info("updateCvn_2 : specific update for EntityProfile = " + pkiEntityProfile.getName());
            xmlEntityProfile.setId(pkiEntityProfile.getId());
            return xmlEntityProfile;

        }

        return null;

    }

}
