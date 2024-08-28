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
package com.ericsson.oss.itpf.security.credmservice.util;

import java.io.File;
import java.io.FileFilter;

public class XmlFileFilter implements FileFilter {

    static private final String EXTENSION_TAG = "xml";

    @Override
    public boolean accept(final File file) {

        return file.getName().toLowerCase().endsWith(EXTENSION_TAG);
    }

    public boolean acceptXml(final File file) {
        return file.getName().toLowerCase().endsWith(EXTENSION_TAG);
    }
}
