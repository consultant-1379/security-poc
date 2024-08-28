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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiNameValueCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

/**
 * 
 * This class will add the Trust profiles information in PkiNameValueCommandResponse object.
 * 
 * @author tcschsa
 */
public class TrustProfileViewCommandResponse {

    @Inject
    private Logger logger;

    @Inject
    CommandHandlerUtils commandHandlerUtils;

    private static final String TRUST_PROFILE_DATA = "Trust Profile Data::";
    private static final String INTERNAL_CA = "Internal CA: ";
    private static final String EXTERNAL_CA = "External CA: ";

    /**
     * Method to build the command response for viewing the trust profile data
     * 
     * 
     * @param trustProfile
     * @return PkiNameValueCommandResponse
     * 
     */
    public PkiNameValueCommandResponse buildCommandResponseForTrustProfile(final TrustProfile trustProfile) {

        final PkiNameValueCommandResponse commandResponse = new PkiNameValueCommandResponse();

        commandResponse.add(TRUST_PROFILE_DATA, Constants.EMPTY_STRING);
        commandResponse.add(Constants.NAME_VIEW, trustProfile.getName());
        commandResponse.add(Constants.IS_ACTIVE, ValidationUtils.isTrueOrFalse(trustProfile.isActive()));
        commandResponse.add(Constants.MODIFIABLE_VIEW, ValidationUtils.isTrueOrFalse(trustProfile.isModifiable()));
        commandResponse.add(Constants.PROFILE_VALIDITY, (null != trustProfile.getProfileValidity() ? commandHandlerUtils.getDateString(trustProfile.getProfileValidity()) : Constants.EMPTY_STRING));
        commandResponse.add(INTERNAL_CA, getInternalTrustChainList(trustProfile.getTrustCAChains()));
        commandResponse.add(EXTERNAL_CA, getExternalTrustChainList(trustProfile.getExternalCAs()));
        return commandResponse;
    }

    private String getExternalTrustChainList(final List<ExtCA> externalCAs) {

        if (ValidationUtils.isNullOrEmpty(externalCAs)) {
            return Constants.EMPTY_STRING;
        }

        final List<String> externalTrustChains = new ArrayList<>();
        for (final ExtCA externalCAChain : externalCAs) {
            externalTrustChains.add(externalCAChain.getCertificateAuthority().getName());
        }
        return CommandHandlerUtils.getFieldValues(externalTrustChains, Constants.COMMA);
    }

    private String getInternalTrustChainList(final List<TrustCAChain> trustCAChains) {

        if (ValidationUtils.isNullOrEmpty(trustCAChains)) {
            return Constants.EMPTY_STRING;
        }
        final List<String> internalTrustChains = new ArrayList<>();
        for (final TrustCAChain trustCAChain : trustCAChains) {
            internalTrustChains.add(trustCAChain.getInternalCA().getCertificateAuthority().getName());
        }
        return CommandHandlerUtils.getFieldValues(internalTrustChains, Constants.COMMA);
    }

}
