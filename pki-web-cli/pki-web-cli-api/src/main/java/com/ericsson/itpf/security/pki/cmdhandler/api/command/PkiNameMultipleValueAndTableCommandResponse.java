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

package com.ericsson.itpf.security.pki.cmdhandler.api.command;


import java.util.*;

/**
 * <p>
 * A subclass of PKICommandResponse representing a list of name/ multiple value pairs .
 * </p>
 *
 */
public class PkiNameMultipleValueAndTableCommandResponse extends PkiCommandResponse {

    private static final long serialVersionUID = 1L;
    private final List<PkiNameMultipleValueCommandResponse> multipleValuesList = new LinkedList<>();

    /**
     * Always returns PkiCommandResponseType.NAME_MULTIPLE_VALUE
     *
     * @return PkiCommandResponseType.NAME_MULTIPLE_VALUE
     */
    @Override
    public PKICommandResponseType getResponseType() {
        return PKICommandResponseType.NAME_MULTIPLE_VALUE_AND_TABLE;
    }


    public void add(final PkiNameMultipleValueCommandResponse pkiNameMultipleValueCommandResponse) {
        multipleValuesList.add(pkiNameMultipleValueCommandResponse);
    }

    public boolean isEmpty() {
        return multipleValuesList.isEmpty();
    }
    /**
     * @return the multipleValuesList
     */
    public List<PkiNameMultipleValueCommandResponse> getMultipleValuesList() {
        return multipleValuesList;
    }

}
