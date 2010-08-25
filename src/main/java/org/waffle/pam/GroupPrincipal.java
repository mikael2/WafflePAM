package org.waffle.pam;

import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author mikael
 */
public class GroupPrincipal implements Principal {
    String name;
    String username;

    Set<String> groups;

    public GroupPrincipal(String name, String username) {
        this.name = name;
        this.username = username;
        this.groups = new HashSet<String>();
    }


    public String getName() {
        return name;
    }

    public String getUsername() {
        return username;
    }


    public void addGroups(String... groups) {
        Collections.addAll(this.groups,groups);
    }

    public String[] getGroups() {
        return groups.toArray(new String[groups.size()]);
    }

    public boolean hasGroup(String group) {
        return groups.contains(group);
    }

    @Override
    public String toString() {
        return getName();
    }
}
