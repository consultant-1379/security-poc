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
 * A subclass of PkiCommandResponse representing a list of name/value pairs .
 * </p>
 * 
 * @author xsumnan on 29/03/2015.
 */
public class PkiNameValueCommandResponse extends PkiCommandResponse implements Iterable<PkiNameValueCommandResponse.Entry> {

    private static final long serialVersionUID = -1673990240029588019L;

    private final List<Entry> pairs = new LinkedList<>();

    public PkiNameValueCommandResponse add(final String name, final String value) {
        pairs.add(new Entry(name, value));
        return this;
    }

    /**
     * Always returns PkiCommandResponseType.NAME_VALUE
     * 
     * @return PkiCommandResponseType.NAME_VALUE
     */
    @Override
    public PKICommandResponseType getResponseType() {
        return PKICommandResponseType.NAME_VALUE;
    }

    /**
     * @return a Iterator of PkiNameValueCommandResponse.Entry, where each Entry is a name-value pair.
     */
    @Override
    public Iterator<Entry> iterator() {
        return pairs.iterator();
    }

    /**
     * @return the number of name/value pairs in this response
     */
    public int size() {
        return pairs.size();
    }

    /**
     * @return true if this response has no name/value pair in it.
     */
    public boolean isEmpty() {
        return pairs.isEmpty();
    }

    /**
     * Represents a Name/Value pair
     */
    public class Entry implements Serializable {
        private static final long serialVersionUID = 4092596821283304666L;

        private final String name;
        private final String value;

        public Entry(final String name, final String value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * Comparator implementation for Entry
     * 
     * @author xsumnan
     * 
     */
    public class EntryComparator implements Comparator<Entry> {

        @Override
        public int compare(final Entry arg0, final Entry arg1) {

            final int value1 = arg0.getValue().compareTo(arg1.getValue());

            if (value1 == 0) {
                final int value2 = arg0.getName().compareTo(arg1.getName());
                if (value2 != 0) {
                    return value2;
                }
            }
            return value1;
        }
    }
}
