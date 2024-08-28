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
package com.ericsson.oss.itpf.security.credmservice.test.util;

public class Samples {
    final private Object sampleA;
    final private Object sampleB;

    public Samples(final Object a, final Object b) {
        sampleA = a;
        sampleB = b;
    }

    public Object getSampleA() {
        return sampleA;
    }

    public Object getSampleB() {
        return sampleB;
    }
}
