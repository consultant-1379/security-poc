/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.kaps.common.persistence.handler;

import java.math.BigInteger;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.kaps.common.persistence.KAPSExternalPersistenceManager;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;

/**
 * Handler class to do the DB operations related to key management.
 */
public class TAFKeyPairPersistenceHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(TAFKeyPairPersistenceHandler.class);

    @Inject
    KAPSExternalPersistenceManager kapsExternalPersistenceManager;

    public void deleteTAFCaKeys(final List<String> keyIds) throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        try {
            LOGGER.info("Start of deleting TAF CA keys data");

            final String keyPairInfoDeleteQuery = "delete from keypair_info where keyidentifier = :keyIdentifierId";
            final String encryptedPrivateKeyInfoDeleteQuery = "delete from encrypted_privatekey_info where id= :encryptedPrivateKeyInfoId";

            for (String keyId : keyIds) {
                final String queryForKeyIdentifier = (String) kapsExternalPersistenceManager.createNativeQuery(
                        "SELECT keyidentifier from keypair_info where keyidentifier='" + keyId + "'").get(0);
                final BigInteger queryForEncryptedPrivateKeyInfoId = (BigInteger) kapsExternalPersistenceManager.createNativeQuery(
                        "SELECT encrypted_privatekey_info_id  from keypair_info where keyidentifier='" + queryForKeyIdentifier + "'").get(0);

                kapsExternalPersistenceManager.getEntityManager().createNativeQuery(keyPairInfoDeleteQuery)
                        .setParameter("keyIdentifierId", queryForKeyIdentifier).executeUpdate();
                kapsExternalPersistenceManager.getEntityManager().createNativeQuery(encryptedPrivateKeyInfoDeleteQuery)
                        .setParameter("encryptedPrivateKeyInfoId", queryForEncryptedPrivateKeyInfoId).executeUpdate();
            }

            LOGGER.info("End of deleting TAF CA keys data");
        } catch (Exception exception) {
            LOGGER.error("Error occured while deleting TAF CA keys from kaps DB" + exception.getMessage(), exception);
        }

    }

}