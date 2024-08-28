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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common;

import java.util.concurrent.ConcurrentHashMap;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.security.pki.ra.cmp.asynchresponse.RestSynchResponse;

@ApplicationScoped
public class CMPTransactionResponseMap {

    private final ConcurrentHashMap<String, RestSynchResponse> cmpResponseMap = new ConcurrentHashMap<>();

    public RestSynchResponse getRestSynchResponse(final String transactionID) {
        final RestSynchResponse response = cmpResponseMap.get(transactionID);
        cmpResponseMap.remove(transactionID);
        return response;
    }

    public void putRestSynchResponse(final String transactionId, final RestSynchResponse response) {
        cmpResponseMap.put(transactionId, response);
    }

    public boolean isTransactionIdExists(final String transactionId) {
        return cmpResponseMap.containsKey(transactionId);
    }

}
