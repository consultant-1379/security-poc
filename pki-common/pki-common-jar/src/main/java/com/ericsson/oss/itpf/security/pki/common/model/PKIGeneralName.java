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
package com.ericsson.oss.itpf.security.pki.common.model;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * This class is used to set the GeneralName
 * 
 * @author tcsramc
 * 
 */
public class PKIGeneralName extends GeneralName {
    /**
     * This constructor is used to set the general name
     * 
     * @param name
     *            It is a X500Name Object
     */
    public PKIGeneralName(final X500Name name) {
        super(name);
    }

}
