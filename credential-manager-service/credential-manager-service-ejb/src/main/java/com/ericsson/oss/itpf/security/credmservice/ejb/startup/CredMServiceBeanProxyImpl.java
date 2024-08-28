/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.ejb.startup;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerCheckException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerDbUpgradeException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerStartupException;
import com.ericsson.oss.itpf.security.credmservice.util.CredMPkiConfInitializer;

@Stateless
public class CredMServiceBeanProxyImpl implements CredMServiceBeanProxy {

    @Inject
    private CredMPkiConfInitializer credMPkiConfInitializer;

    @Inject
    CredMServiceSelfCredentialsManager credMServiceSelfCredentialsManager;
    private static final Logger log = LoggerFactory.getLogger(CredMServiceBeanProxyImpl.class);
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void generateJBossCredentials() throws CredentialManagerStartupException {
        credMServiceSelfCredentialsManager.generateJBossCredentials();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void pkiDbUpgrade() throws CredentialManagerDbUpgradeException{

    	credMPkiConfInitializer.upgrade();

    }

    @Override
    public void checkDbCvnStatus() {
    	credMPkiConfInitializer.checkDbCvnStatus();
    }
    @Override
    public void checkJBossCredentials() throws CredentialManagerCheckException {
        if (!CredMServiceSelfCredentialsManager.checkCertificateValidity()) {
            throw new CredentialManagerCheckException("Expired certificates");
        }
        if (!credMServiceSelfCredentialsManager.checkTrustValidity()) {
            throw new CredentialManagerCheckException("Truststore not present");
        }
        if (!credMServiceSelfCredentialsManager.checkJbossEntityReissueState()) {
            throw new CredentialManagerCheckException("Certificate has to be reissued");
        }
        if (!credMServiceSelfCredentialsManager.checkTrusts()) {
            throw new CredentialManagerCheckException("Invalid trusts");
        }
    }
}
