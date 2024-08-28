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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CRLDistributionPoints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPoint;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidCRLDistributionPointsException;

/**
 * This class builds {@link CRLDistPoint} extension for the certificate.
 * 
 */
public class CRLDistributionPointsBuilder {

    @Inject
    Logger logger;

    /**
     * Builds {@link CRLDistributionPoints} from the certificate extension passed.
     * 
     * @param certificateExtension
     *            certificate extension that to be built as {@link CRLDistributionPoints}
     * @return Extension that has {@link CRLDistributionPoints} object.
     * @throws InvalidCRLDistributionPointsException
     *             Thrown incase if any failures occur in building extension.
     */

    public Extension buildCRLDistributionPoints(final CertificateExtension certificateExtension) throws InvalidCRLDistributionPointsException {

        final CRLDistributionPoints cRLDistributionPoints = (CRLDistributionPoints) certificateExtension;

        logger.debug("Adding CRLDistributionPoints extension to certificate extensions {} ", cRLDistributionPoints);

        final List<DistributionPoint> distributionPoints = cRLDistributionPoints.getDistributionPoints();

        final List<org.bouncycastle.asn1.x509.DistributionPoint> distributionPointNames = new ArrayList<>();
        ReasonFlags reasonFlag = null;
        Extension extension = null;
        for (final DistributionPoint distributionPoint : distributionPoints) {
            final ReasonFlag reasonFlg = distributionPoint.getReasonFlag();
            if (reasonFlg != null) {
                reasonFlag = new ReasonFlags(getReasonCodes(reasonFlg));
            }

            if (distributionPoint.getDistributionPointName() != null) {
                //The code is commented out because currently only FullName is supported and CRL issuer will be supported later. User story NO:110718

                getDistributionsPointByFullNames(distributionPoint, distributionPointNames, reasonFlag);
              //getDistributionsPointByNameRelativeToCRLIssuer(distributionPoint, distributionPointNames, reasonFlag);

            } /*
               * else if (distributionPoint.getCRLIssuer() != null) { getDistributionsPointByCRLIssuer(distributionPoint, distributionPointNames, reasonFlag); }
               */
        }
        final CRLDistPoint cRLDistPoint = new CRLDistPoint(distributionPointNames.toArray(new org.bouncycastle.asn1.x509.DistributionPoint[0]));
        try {
            extension = new Extension(Extension.cRLDistributionPoints, cRLDistributionPoints.isCritical(), new DEROctetString(cRLDistPoint));

            return extension;
        } catch (IOException ioException) {
            logger.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, ioException);
            throw new InvalidCRLDistributionPointsException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
        }
    }

    private int getReasonCodes(final ReasonFlag reasonFlag) throws InvalidCRLDistributionPointsException {

        switch (reasonFlag) {
        case UNUSED:
            return ReasonFlags.unused;
        case KEY_COMPROMISE:
            return ReasonFlags.keyCompromise;
        case CA_COMPROMISE:
            return ReasonFlags.cACompromise;
        case AFFILIATION_CHANGED:
            return ReasonFlags.affiliationChanged;
        case SUPERSEDED:
            return ReasonFlags.superseded;
        case CESSATION_OF_OPERATION:
            return ReasonFlags.cessationOfOperation;
        case CERTIFICATE_HOLD:
            return ReasonFlags.certificateHold;
        case PRIVILEGE_WITHDRAWN:
            return ReasonFlags.privilegeWithdrawn;
        case AA_COMPROMISE:
            return ReasonFlags.aACompromise;
        default:
            throw new InvalidCRLDistributionPointsException(ErrorMessages.INVALID_REASON_CODE);
        }
    }

    private void getDistributionsPointByFullNames(final DistributionPoint distributionPoint, final List<org.bouncycastle.asn1.x509.DistributionPoint> distributionPointNames,
            final ReasonFlags reasonFlag) {

        final List<GeneralName> cRLGeneralNameList = new ArrayList<>();

        if (distributionPoint.getDistributionPointName().getFullName() != null && !distributionPoint.getDistributionPointName().getFullName().isEmpty()) {

            final List<String> cRLUrls = distributionPoint.getDistributionPointName().getFullName();

            for (final String cRlUrl : cRLUrls) {
                cRLGeneralNameList.add(new GeneralName(GeneralName.uniformResourceIdentifier, cRlUrl));
            }
            final GeneralNames cRLGeneralNames = new GeneralNames(cRLGeneralNameList.toArray(new GeneralName[0]));
            final org.bouncycastle.asn1.x509.DistributionPointName distributionPointName = new org.bouncycastle.asn1.x509.DistributionPointName(
                    org.bouncycastle.asn1.x509.DistributionPointName.FULL_NAME, cRLGeneralNames);

            distributionPointNames.add(new org.bouncycastle.asn1.x509.DistributionPoint(distributionPointName, reasonFlag, null));
        }
    }

    /*
     * private void getDistributionsPointByNameRelativeToCRLIssuer(final DistributionPoint distributionPoint, final List<org.bouncycastle.asn1.x509.DistributionPoint> distributionPointNames, final
     * ReasonFlags reasonFlag) {
     * 
     * if (distributionPoint.getDistributionPointName().getNameRelativeToCRLIssuer() != null && !distributionPoint.getDistributionPointName().getNameRelativeToCRLIssuer().isEmpty()) {
     * 
     * final List<GeneralName> cRLGeneralNameList = new ArrayList<GeneralName>();
     * 
     * cRLGeneralNameList.add(new GeneralName(new X500Name(distributionPoint.getDistributionPointName().getNameRelativeToCRLIssuer())));
     * 
     * final GeneralNames cRLGeneralNames = new GeneralNames(cRLGeneralNameList.toArray(new GeneralName[0]));
     * 
     * final org.bouncycastle.asn1.x509.DistributionPointName distributionPointName = new org.bouncycastle.asn1.x509.DistributionPointName(
     * org.bouncycastle.asn1.x509.DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER, cRLGeneralNames);
     * 
     * distributionPointNames.add(new org.bouncycastle.asn1.x509.DistributionPoint(distributionPointName, reasonFlag, null)); } }
     * 
     * private void getDistributionsPointByCRLIssuer(final DistributionPoint distributionPoint, final List<org.bouncycastle.asn1.x509.DistributionPoint> distributionPointNames, final ReasonFlags
     * reasonFlag) {
     * 
     * final GeneralName cRLIssuerGeneralName = new GeneralName(new X500Name(distributionPoint.getCRLIssuer()));
     * 
     * final GeneralNames cRLGeneralNames = new GeneralNames(cRLIssuerGeneralName);
     * 
     * distributionPointNames.add(new org.bouncycastle.asn1.x509.DistributionPoint(null, reasonFlag, cRLGeneralNames)); }
     */
}
