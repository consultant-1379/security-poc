/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.scriptengine.api;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.services.scriptengine.spi.dtos.AbstractDto;

public class CommandResponse implements Serializable {

    private static final long serialVersionUID = 1912693191659134200L;

    private final List<AbstractDto> elements;
    private final List<AbstractDto> nonCachableDtos;

    public CommandResponse(final List<AbstractDto> dtos, final List<AbstractDto> nonCachableDtos) {
        this.elements = new ArrayList<>();
        this.elements.addAll(dtos);

        this.nonCachableDtos = new ArrayList<>();
        this.nonCachableDtos.addAll(nonCachableDtos);
    }

    public List<AbstractDto> getElements() {
        return elements;
    }

    public List<AbstractDto> getNonCachableDtos() {
        return nonCachableDtos;
    }

    @Override
    public boolean equals(final Object other) {

        boolean isEquals = true;

        if (this == other) {
            return isEquals;
        }

        if (!(other instanceof CommandResponse)) {
            isEquals = false;
            return isEquals;
        }

        final CommandResponse that = (CommandResponse) other;

        if (!getElements().equals(that.getElements())) {
            isEquals = false;
            return isEquals;
        }

        if (!getNonCachableDtos().equals(that.getNonCachableDtos())) {
            isEquals = false;
            return isEquals;
        }

        return isEquals;
    }

    @Override
    public int hashCode() {

        final int getElementsResult = getElements().hashCode();
        final int getNonCachableDtosResult = getNonCachableDtos().hashCode();

        return 31 * getElementsResult + getNonCachableDtosResult;
    }
}
