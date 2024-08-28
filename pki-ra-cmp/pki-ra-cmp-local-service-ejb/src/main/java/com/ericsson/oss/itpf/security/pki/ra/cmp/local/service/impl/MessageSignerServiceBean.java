/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.impl;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.ResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ProtectionEncodingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.InvalidInitialConfigurationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.ResponseMessageSigningHelper;
import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.MessageSignerService;

/**
 * This class implements the local interface MessageSignerService.
 * 
 * @author 1210241
 */
@Stateless
public class MessageSignerServiceBean implements MessageSignerService {

    @Inject
    ResponseMessageSigningHelper responseMessageSigningHelper;

    @Override
    public byte[] signMessage(final String issuerName, final ResponseMessage responseMessage)
            throws InvalidInitialConfigurationException, IOException, ProtectionEncodingException, ResponseSignerException {
        return responseMessageSigningHelper.signMessage(issuerName, responseMessage);
    }

    @Override
    public String getSenderFromSignerCert(final String issuerName) throws InvalidInitialConfigurationException {
        return responseMessageSigningHelper.getSenderFromSignerCert(issuerName);
    }

    @Override
    public List<X509Certificate> buildCMPExtraCertsForResponseFromManager(final String issuerName, final ResponseMessage pKIResponseMessage)
            throws CertificateException, InvalidInitialConfigurationException, IOException {
        return responseMessageSigningHelper.buildCMPExtraCertsForResponseFromManager(issuerName, pKIResponseMessage);
    }
}
