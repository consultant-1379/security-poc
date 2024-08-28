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
package com.ericsson.oss.itpf.security.pki.manager.common.setupdata;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;

public class ExtCASetUpData {

    /**
     * Method that returns valid ExtCA
     * 
     * @return ExtCA
     * @throws ParseException
     */
    public ExtCA getExtCAForEqual() throws ParseException {
        final ExtCA extCA = new ExtCA();
        extCA.setCertificateAuthority(new CertificateAuthoritySetUpData().name("equal").build());
        final ExtCA extCA2 = new ExtCA();
        extCA2.setCertificateAuthority(new CertificateAuthoritySetUpData().name("extCA2").build());
        final List<ExtCA> extCAs = new ArrayList();
        extCAs.add(extCA2);
        extCA.setAssociated(extCAs);
        final ExternalCRLInfo externalCRLInfo = new ExternalCRLInfoSetUpData().getExternalCRLInofForCreate();
        extCA.setExternalCRLInfo(externalCRLInfo);
        return extCA;
    }

    /**
     * Method that returns valid ExtCA
     * 
     * @return ExtCA
     */
    public ExtCA getExtCAForNotEqual() {
        final ExtCA extCA = new ExtCA();
        extCA.setCertificateAuthority(new CertificateAuthoritySetUpData().name("notEqual").build());
        final ExtCA extCA2 = new ExtCA();
        extCA2.setCertificateAuthority(new CertificateAuthoritySetUpData().name("extCA2").build());
        final List<ExtCA> extCAs = new ArrayList();
        extCAs.add(extCA2);
        extCA.setAssociated(extCAs);
        return extCA;
    }
}
