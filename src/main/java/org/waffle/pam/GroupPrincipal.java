package org.waffle.pam;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import waffle.servlet.WindowsPrincipal;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.PrincipalFormat;

/**
 *
 * @author mikael
 */
public class GroupPrincipal extends WindowsPrincipal implements Serializable {
    Set<String> roles;

    protected GroupPrincipal() {
        super(null,null,null);
    }


    public GroupPrincipal(IWindowsIdentity identity, PrincipalFormat principalFormat, PrincipalFormat roleFormat) {
        super(identity,principalFormat,roleFormat);
        roles = new HashSet<String>();
    }


    public void addRoles(String... roles) {
        Collections.addAll(this.roles,roles);
    }


    public boolean hasRole(String role) {
        return roles.contains(role) || super.getRolesString().contains(role);
    }

    public String[] getRoles() {
        Set<String> retVal = new HashSet<String>();

        retVal.addAll(roles);
        String roleStr = super.getRolesString();
        Collections.addAll(retVal, roleStr.split(", "));

        return retVal.toArray(new String[retVal.size()]);
    }

    public String getSimpleName() {
        String retVal = super.getName();
        int index = retVal.indexOf('\\');
        return index == -1 ? retVal : retVal.substring(index+1);
    }

    @Override
    public String getName() {
        return getSimpleName();
    }



    @Override
    public String toString() {
        return getName();
    }
}
