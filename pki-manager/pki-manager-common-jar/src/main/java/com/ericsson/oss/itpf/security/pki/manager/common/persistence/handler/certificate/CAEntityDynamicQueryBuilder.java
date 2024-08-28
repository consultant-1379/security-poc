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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate;

import java.util.*;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.DynamicQueryBuilder;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;

public class CAEntityDynamicQueryBuilder extends DynamicQueryBuilder {

    /**
     * @param dnBasedCertificateIdentifier
     *            The {@link DNBasedCertificateIdentifier}
     * @param dynamicQuery
     *            dynamic Query String
     * @return returns dynamicQuery appended with given Criteria's
     */
    public Map<String, Object> where(final DNBasedCertificateIdentifier dnBasedCertificateIdentifier, final StringBuilder dynamicQuery) {
        final List<String> clauses = new ArrayList<String>();
        final Map<String, Object> parameters = new HashMap<String, Object>();

        if (dnBasedCertificateIdentifier.getSubjectDN() != null) {
            addCriteria("ced.certificateAuthorityData.subjectDN", "=", dnBasedCertificateIdentifier.getSubjectDN(), "subjectDN", clauses, parameters);
        }

        if (dnBasedCertificateIdentifier.getIssuerDN() != null) {
            addCriteria("iced.certificateAuthorityData.subjectDN", "=", dnBasedCertificateIdentifier.getIssuerDN(), "issuerDN", clauses, parameters);
        }

        if (dnBasedCertificateIdentifier.getCerficateSerialNumber() != null) {
            addCriteria("certs.serialNumber", "=", dnBasedCertificateIdentifier.getCerficateSerialNumber(), "serial_number", clauses, parameters);
        }

        if (!clauses.isEmpty()) {
            dynamicQuery.append(" WHERE ").append(addCriterias(clauses.toArray(new String[0]), " and "));
        }
        return parameters;
    }

}
