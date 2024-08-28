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
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.business;

import java.util.*;

public class ActionListManager {

    private List<Actions> actions = new ArrayList<Actions>();

    public boolean addAction(final Actions item) {
        if (!this.actions.contains(item)) {
            this.actions.add(item);
            return true;
        }
        return false;
    }

    public int size() {
        return this.actions.size();
    }

    public boolean isEmpty() {
        return this.actions.isEmpty();
    }

    /**
     * @return the actions
     */
    public List<Actions> getActions() {
        return this.actions;
    }

    /**
     * @param actions
     *            the actions to set
     */

    public void setActions(final List<Actions> actions) {
        if (actions != null) {
            this.actions = actions;
        }
    }

    public void setAddActions(final List<Actions> actions) {
        if (actions != null) {
            final Iterator<Actions> i = actions.iterator();
            while (i.hasNext()) {
                this.actions.add(i.next());
            }
        }
    }

    public void clearActionsList() {
        this.actions.clear();
    }

    /**
     * @param actions
     *            the actions to set
     */
    public void addListActionsNoDuplicate(final List<Actions> actions) {
        final Iterator<Actions> i = actions.iterator();
        while (i.hasNext()) {
            this.addAction(i.next());
        }
    }

}
