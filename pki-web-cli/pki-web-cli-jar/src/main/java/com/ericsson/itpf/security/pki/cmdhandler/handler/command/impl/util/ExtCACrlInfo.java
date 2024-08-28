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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ExtCACrlInfo {

    String responseCrlIssuer;
    String nextUpdate;
    String updateUrl;
    String thisUpdate;

    public String getResponseCrlIssuer() {
        return responseCrlIssuer;
    }

    public void setResponseCrlIssuer(final String responseCrlIssuer) {
        this.responseCrlIssuer = responseCrlIssuer;
    }

    public String getNextUpdate() {
        return nextUpdate;
    }

    public void setNextUpdate(final Date nextUpdate) {

        this.nextUpdate = transformDateToString(nextUpdate);
    }

    public String getUpdateUrl() {
        if (updateUrl == null || updateUrl.isEmpty()) {
            return "--";
        }
        return updateUrl;
    }

    public void setUpdateUrl(final String updateUrl) {
        this.updateUrl = updateUrl;
    }

    public String getThisUpdate() {
        return thisUpdate;
    }

    public void setThisUpdate(final Date thisUpdate) {
        this.thisUpdate = transformDateToString(thisUpdate);
    }

    public String transformDateToString(final Date date) {
        final DateFormat df = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");

        return df.format(date);
    }
}
