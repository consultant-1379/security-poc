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
package com.ericsson.oss.itpf.security.pki.common.model.certificate.extension;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.AuthorityInformationAccessSetUpData;

/**
 * This class is used to run Junits for AuthorityInformationAccess objects in different scenarios
 */
public class AuthorityInformationAccessTest extends EqualsTestCase {

    AuthorityInformationAccessSetUpData authorityInformationAccessSetUpData = new AuthorityInformationAccessSetUpData();

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    public Object createInstance() {

        return authorityInformationAccessSetUpData.getAuthorityInformationAccessForEqual(true);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    public Object createNotEqualInstance() {
        return authorityInformationAccessSetUpData.getAuthorityInformationAccessForNotEqual(false);
    }

}
