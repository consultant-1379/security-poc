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

package com.ericsson.itpf.security.pki.cmdhandler.api.command;

import java.io.Serializable;
import java.util.*;

/**
 * <p>
 * A subclass of PKICommandResponse representing a list of name/ multiple value pairs .
 * </p>
 * 
 * @author xsumnan on 29/03/2015.
 */
public class PkiNameMultipleValueCommandResponse extends PkiCommandResponse implements Iterable<PkiNameMultipleValueCommandResponse.Entry> {

    private static final long serialVersionUID = -2469395226834506479L;

    private static final String EMPTY_STRING = "";
    private final List<Entry> pairs = new LinkedList<>();
    private final int numberOfCoulmns;
    private String responseTitle = EMPTY_STRING;

    private String additionalInformation = EMPTY_STRING;

    /**
     * 
     * @param name
     * @param values
     *            Only first NUNMBER_OF_VALUES values will be considered rest of the values ignored
     * @return
     */
    public PkiNameMultipleValueCommandResponse add(final String name, final String[] values) {
        if (values.length == this.numberOfCoulmns) {
            pairs.add(new Entry(name, values));
            return this;
        } else if (values.length > this.numberOfCoulmns) {
            pairs.add((new Entry(name, Arrays.copyOfRange(values, 0, numberOfCoulmns))));
            return this;
        } else {
            throw new IllegalArgumentException("Error: Number of Values provided is less than the Number of Columns defined for this response type");
        }

    }

    /**
     * @return a Iterator of PkiNameMultipleValueCommandResponse.Entry, where each Entry is a name- multiple value pair.
     */
    @Override
    public Iterator<Entry> iterator() {
        return pairs.iterator();
    }

    /**
     * Always returns PkiCommandResponseType.NAME_MULTIPLE_VALUE
     * 
     * @return PkiCommandResponseType.NAME_MULTIPLE_VALUE
     */
    @Override
    public PKICommandResponseType getResponseType() {
        return PKICommandResponseType.NAME_MULTIPLE_VALUE;
    }

    /**
     * @return the number of value corresponding to each name in the response
     */
    public int getValueSize() {
        return numberOfCoulmns;
    }

    /**
     * @return the number of name/ multiple value pairs in this response
     */
    public int size() {
        return pairs.size();
    }

    /**
     * @return true if this response has no name/multiple value pair in it.
     */
    public boolean isEmpty() {
        return pairs.isEmpty();
    }

    /**
     * @return the responseHeaderTitle
     */
    public String getResponseTitle() {
        return responseTitle;
    }

    /**
     * @param responseHeaderTitle
     *            the responseHeaderTitle to set
     */
    public void setResponseHeaderTitle(final String responseTitle) {
        this.responseTitle = responseTitle;
    }

    /**
     * Method for setting number of columns
     * 
     * @param numberOfCoulmns
     */
    public PkiNameMultipleValueCommandResponse(final int numberOfCoulmns) {
        this.numberOfCoulmns = numberOfCoulmns;

    }

    /**
     * Method to get additionalInformation
     * 
     * @return {@link String} the additionalInformation
     */
    public String getAdditionalInformation() {
        return additionalInformation;
    }

    /**
     * Method to set additionalInformation
     * 
     * @param additionalInformation
     *            :the additionalInformation to set
     */
    public void setAdditionalInformation(final String additionalInformation) {
        this.additionalInformation = additionalInformation;
    }

    /**
     * Represents a Name/Multiple Value pair
     */
    public class Entry implements Serializable {

        private static final long serialVersionUID = -4191650207988637354L;
        private final String name;
        private final String[] values;

        public Entry(final String name, final String[] values) {
            this.name = name;
            this.values = values;
        }

        public String getName() {
            return name;
        }

        public String[] getValues() {
            return values;
        }
    }
}
