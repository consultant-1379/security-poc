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
package com.ericsson.oss.itpf.security.pki.ra.scep.constants;

/**
 * This class specifies the Message Type's which are supported by SCEP protocol requests. This Message Type values are defined according to SCEP Draft. getMessageType method returns the messageType
 * integer value to know the message type which is defined by SCEP Draft in request.
 *
 * @author xtelsow
 */
public enum MessageType {
    PKCSREQ(19), CERTREP(3),

    GETCERTINITIAL(20),

    GETCERT(21),

    GETCRL(22);

    public int messageType;

    MessageType(final int value) {
        this.messageType = value;
    }

    /**
     * @return the messageType
     */
    public int getMessageType() {
        return messageType;
    }

    /**
     *
     * @param value
     * @return MessageType
     */
    public static MessageType getNameByValue(final int value) {
        for (final MessageType msgType : MessageType.values()) {
            if (msgType.messageType == value) {
                return msgType;
            }
        }
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Enum#toString()
     */
    @Override
    public String toString() {
        return name();
    }

}
