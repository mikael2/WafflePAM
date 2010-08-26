package org.waffle.pam;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import waffle.servlet.WindowsPrincipal;
import waffle.servlet.spi.SecurityFilterProvider;
import waffle.servlet.spi.SecurityFilterProviderCollection;
import waffle.util.AuthorizationHeader;
import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.PrincipalFormat;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

/**
 *
 * @author mikael
 */
public class WaffleAuthModule extends AbstractHTTPServerAuthModule {
    public static final String MODULENAME = "WaffleAuthModule";
    public static final String BASE_DN    = "basedn";
    public static final String REALM      = "realm";

    private static final String PRINCIPAL_SESSION_KEY = WaffleAuthModule.class.getName() + ".PRINCIPAL";

    private static final Object initLock = new Object();
    private static PrincipalFormat principalFormat = PrincipalFormat.fqn;
    private static PrincipalFormat roleFormat = PrincipalFormat.fqn;
    private static SecurityFilterProviderCollection providers = null;
    private static IWindowsAuthProvider auth = new WindowsAuthProviderImpl();
    private static boolean allowGuestLogin = false;

    static final Logger log = Logger.getLogger(WaffleAuthModule.class.getName());

    DirContext ctx;
    String basedn;
    String realmName;

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options) throws AuthException {
        super.initialize(requestPolicy, responsePolicy, handler, options);

        if (options != null && options.get(Context.PROVIDER_URL) != null) {
            basedn      = (String) options.get(BASE_DN);
            realmName   = (String) options.get(REALM);

            if(basedn == null)
                basedn = "ou=People,dc=example,dc=com";

            if(realmName == null)
                realmName = "exie";

            Hashtable env = new Hashtable();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.PROVIDER_URL,         options.get(Context.PROVIDER_URL));
            env.put(Context.SECURITY_PRINCIPAL,   options.get(Context.SECURITY_PRINCIPAL));
            env.put(Context.SECURITY_CREDENTIALS, options.get(Context.SECURITY_CREDENTIALS));
            try {
                ctx = new InitialDirContext(env);
            } catch (NamingException ex) {
                log.log(Level.SEVERE, ex.getMessage(), ex);
            }
        }

        synchronized(initLock) {
            if(providers == null) {
                Map<String, String> implParameters = new HashMap<String, String>();
                if (options != null) {
                    for(Object parameterName : options.keySet()) {
                        if(options.get(parameterName) instanceof String) {
                            String parameterValue = (String) options.get(parameterName);
                            log.log(Level.WARNING, "{0}={1}", new Object[]{parameterName, parameterValue});
                            if (parameterName.equals("principalFormat")) {
                                principalFormat = PrincipalFormat.valueOf(parameterValue);
                            } else if (parameterName.equals("roleFormat")) {
                                roleFormat = PrincipalFormat.valueOf(parameterValue);
                            } else if (parameterName.equals("allowGuestLogin")) {
                                allowGuestLogin = Boolean.parseBoolean(parameterValue);
                            } else if (parameterName.equals("securityFilterProviders")) {
                                providers = new SecurityFilterProviderCollection(parameterValue.split("\n"), auth);
                            } else {
                                implParameters.put((String) parameterName,parameterValue);
                            }
                        }
                    }
                }

                // create default providers if none specified
                if (providers == null) {
                    log.warning("initializing default security filter providers");
                    providers = new SecurityFilterProviderCollection(auth);
                }

                // apply provider implementation parameters
                for (Entry<String, String> implParameter : implParameters.entrySet()) {
                    String[] classAndParameter = implParameter.getKey().split("/", 2);
                    if (classAndParameter.length == 2) {
                        try {
                            log.log(Level.FINE, "setting {0}, {1}={2}", new Object[]{classAndParameter[0], classAndParameter[1], implParameter.getValue()});
                            SecurityFilterProvider provider = providers.getByClassName(classAndParameter[0]);
                            provider.initParameter(classAndParameter[1], implParameter.getValue());
                        } catch (ClassNotFoundException e) {
                            log.log(Level.SEVERE, "invalid class: {0} in {1}", new Object[]{classAndParameter[0], implParameter.getKey()});
                            throw new AuthException(e.getMessage());
                        } catch (Exception e) {
                            log.log(Level.SEVERE, "{0}: error setting ''{1}'': {2}", new Object[]{classAndParameter[0], classAndParameter[1], e.getMessage()});
                            throw new AuthException(e.getMessage());
                        }
                    }
                }
            }
        }
    }



    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject client, Subject server) throws AuthException {
        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();

        log.log(Level.FINE, "{0} {1}, contentlength: {2}", new Object[]{request.getMethod(), request.getRequestURI(), request.getContentLength()});

        Principal principal = getPrincipal(request);
        if (requestPolicy.isMandatory() == false || principal != null) {
            // Unprotected page, reinstall retVal if found in session
            try {
                setAuthenticationResult(principal, client, messageInfo);
                return AuthStatus.SUCCESS;
            } catch (Exception ex) {
                log.log(Level.SEVERE, ex.getMessage(), ex);
                AuthException ae = new AuthException();
                ae.initCause(ex);
                throw ae;
            }
        }

 
        // authenticate user
        AuthorizationHeader authorizationHeader = new AuthorizationHeader(request);
        if (!authorizationHeader.isNull()) {

            // log the user in using the token
            IWindowsIdentity windowsIdentity = null;
            try {
                windowsIdentity = providers.doFilter(request, response);
                if (windowsIdentity == null) {
                    return AuthStatus.SEND_CONTINUE;
                }
            } catch (Exception e) {
                log.log(Level.WARNING, "error login user: {0}", e.getMessage());
                sendUnauthorized(response, true);
                return AuthStatus.FAILURE;
            }

            try {
                if (!allowGuestLogin && windowsIdentity.isGuest()) {
                    log.log(Level.WARNING, "guest login disabled: {0}", windowsIdentity.getFqn());
                    sendUnauthorized(response, true);
                    return AuthStatus.FAILURE;
                }

                log.log(Level.FINE, "loged in user: {0} ({1})", new Object[]{windowsIdentity.getFqn(), windowsIdentity.getSidString()});

                HttpSession session = request.getSession(true);
                if (session == null) {
                    throw new AuthException("Expected HttpSession");
                }

                Subject subject = (Subject) session.getAttribute("javax.security.auth.subject");
                if (subject == null) {
                    subject = new Subject();
                }

                GroupPrincipal windowsPrincipal = new GroupPrincipal(windowsIdentity, principalFormat, roleFormat);
                addExtraRoles(windowsPrincipal);

                log.log(Level.FINE, "roles: {0}", windowsPrincipal.getRolesString());
                subject.getPrincipals().add(windowsPrincipal);
                session.setAttribute("javax.security.auth.subject", subject);

                log.log(Level.INFO, "successfully logged in user: {0}", windowsIdentity.getFqn());
                request.getSession().setAttribute(PRINCIPAL_SESSION_KEY, windowsPrincipal);
                setAuthenticationResult(windowsPrincipal, client, messageInfo);
                return AuthStatus.SUCCESS;
            } catch(Exception e) {
                log.log(Level.WARNING, "error login user: {0}", e.getMessage());
                sendUnauthorized(response, true);
                return AuthStatus.FAILURE;
            } finally {
                windowsIdentity.dispose();
            }
        }

        log.info("authorization required");
        sendUnauthorized(response, false);
        return AuthStatus.FAILURE;
    }


    /**
     * Filter for a previously logged on user.
     * @param request HTTP request.
     * @return Principal if a user already authenticated.
     */
    private Principal getPrincipal(HttpServletRequest request) {
        Principal retVal = request.getUserPrincipal();
        if (retVal == null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                retVal = (Principal) session.getAttribute(PRINCIPAL_SESSION_KEY);
            }
        }

        if (providers.isPrincipalException(request)) {
            // the providers signal to authenticate despite an existing retVal, eg. NTLM post
            return null;
        }

        // user already authenticated
        if (retVal instanceof WindowsPrincipal) {
            log.log(Level.FINE, "previously authenticated Windows user: {0}", retVal.getName());

        } else if(retVal != null) {
            log.log(Level.FINE, "previously authenticated user: {0}", retVal.getName());
        }

        return retVal;
    }


 
    /**
     * Set the retVal format.
     * @param format
     *  Principal format.
     */
    public void setPrincipalFormat(String format) {
        principalFormat = PrincipalFormat.valueOf(format);
    }

    /**
     * Principal format.
     * @return
     *  Principal format.
     */
    public PrincipalFormat getPrincipalFormat() {
        return principalFormat;
    }

    /**
     * Set the retVal format.
     * @param format
     *  Role format.
     */
    public void setRoleFormat(String format) {
        roleFormat = PrincipalFormat.valueOf(format);
    }

    /**
     * Principal format.
     * @return
     *  Role format.
     */
    public PrincipalFormat getRoleFormat() {
        return roleFormat;
    }

    /**
     * Send a 401 Unauthorized along with protocol authentication headers.
     * @param response
     *  HTTP Response
     * @param close
     *  Close connection.
     */
    private AuthStatus sendUnauthorized(HttpServletResponse response, boolean close) {
        try {
            providers.sendUnauthorized(response);
            if (close) {
                response.setHeader("Connection", "close");
            } else {
                response.setHeader("Connection", "keep-alive");
            }
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            response.flushBuffer();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return AuthStatus.FAILURE;
    }

    /**
     * Windows auth provider.
     * @return
     *  IWindowsAuthProvider.
     */
    public IWindowsAuthProvider getAuth() {
        return auth;
    }

    /**
     * Set Windows auth provider.
     * @param provider
     *  Class implements IWindowsAuthProvider.
     */
    public void setAuth(IWindowsAuthProvider provider) {
        auth = provider;
    }

    /**
     * True if guest login is allowed.
     * @return
     *  True if guest login is allowed, false otherwise.
     */
    public boolean getAllowGuestLogin() {
        return allowGuestLogin;
    }

    /**
     * Security filter providers.
     * @return
     *  A collection of security filter providers.
     */
    public SecurityFilterProviderCollection getProviders() {
        return providers;
    }

    private void setAuthenticationResult(Principal principal, Subject client, MessageInfo messageInfo)
            throws IOException, UnsupportedCallbackException {
        if(principal == null) {
            handler.handle(new Callback[] {new CallerPrincipalCallback(client, principal)});
            messageInfo.getMap().put(AUTH_TYPE_INFO_KEY, MODULENAME);
        } else {
            CallerPrincipalCallback callerPrincipalCallback = new CallerPrincipalCallback(client, principal);
            String[] roles = principal instanceof GroupPrincipal ? ((GroupPrincipal)principal).getRoles() : new String[] {};
            GroupPrincipalCallback groupPrincipalCallback = new GroupPrincipalCallback(client,roles);
            handler.handle(new Callback[]{callerPrincipalCallback, groupPrincipalCallback});
        }
    }

    private void addExtraRoles(GroupPrincipal principal) {
        try {
            if(ctx != null) {
                principal.addRoles(getUserRoles(ctx, principal.getSimpleName()));
            }
        } catch(Throwable t) {
            System.out.println("Error: " + t.getMessage());
            t.printStackTrace();
        }
    }

    public static String[] getUserRoles(DirContext ctx, String uid) {
        ArrayList<String> retVal = new ArrayList<String>();
        try {
            SearchControls ctls = new SearchControls();
            String[] attrIds = {"isMemberOf"};  // OpenDS specific virtual attribute
            ctls.setReturningAttributes(attrIds);
            ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String filter = "(&(objectClass=inetOrgPerson)(uid=" + uid + "))";
            NamingEnumeration<SearchResult> answer = ctx.search("", filter, ctls);
            while(answer.hasMore()) {
                SearchResult searchResult = answer.next();
                NamingEnumeration<? extends Attribute> ne = searchResult.getAttributes().getAll();
                while(ne.hasMore()) {
                    Attribute attr = ne.next();
                    if(attr.size() > 0) {
                        NamingEnumeration ne2 =  attr.getAll();
                        while(ne2.hasMore()) {
                            String line =  ne2.next().toString();
                            if(line.contains("ou=exieroles") || line.contains("ou=j2eeroles")) {
                                int start = line.indexOf("cn=");
                                int end   = line.indexOf(",", start);
                                retVal.add(line.substring(start+3, end));
                            }
                        }
                    }
                }
            }
            answer.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }

        System.out.println("Roles for '" + uid + "'");
        for(String role : retVal) {
            System.out.println("Role: '" + role + "'");
        }

        return retVal.toArray(new String[retVal.size()]);
    }
}
