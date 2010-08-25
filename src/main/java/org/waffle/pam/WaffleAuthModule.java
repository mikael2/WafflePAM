package org.waffle.pam;

import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;
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
import javax.servlet.ServletException;
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
    private static final String MODULENAME = "WaffleAuthModule";
    private static final String PRINCIPAL_SESSION_KEY = WaffleAuthModule.class.getName() + ".PRINCIPAL";


    private PrincipalFormat principalFormat = PrincipalFormat.fqn;
    private PrincipalFormat roleFormat = PrincipalFormat.fqn;
    private SecurityFilterProviderCollection providers = null;
    private IWindowsAuthProvider auth = new WindowsAuthProviderImpl();
    private boolean allowGuestLogin = true;

    static final Logger log = Logger.getLogger(WaffleAuthModule.class.getName());

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options) throws AuthException {
        super.initialize(requestPolicy, responsePolicy, handler, options);

        try {
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
                log.severe("initializing default secuirty filter providers");
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
        } catch(Exception e) {
            log.log(Level.SEVERE,e.getMessage(),e);
        }
    }



    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject client, Subject server) throws AuthException {
        AuthStatus retVal = AuthStatus.FAILURE;

        HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
        HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();
        HttpSession session = request.getSession(false);

        log.log(Level.INFO, "{0} {1}, contentlength: {2}", new Object[]{request.getMethod(), request.getRequestURI(), request.getContentLength()});

        GroupPrincipal principal = null;
        if (requestPolicy.isMandatory() == false || principal != null) {
            // Unprotected page, reinstall principal if found in session
            try {
                setAuthenticationResult(principal, client, messageInfo);
            } catch (Exception ex) {
                log.log(Level.SEVERE, ex.getMessage(), ex);
                AuthException ae = new AuthException();
                ae.initCause(ex);
                throw ae;
            }
        }

        if (doFilterPrincipal(request)) {
            // previously authenticated user
            retVal = AuthStatus.SUCCESS;
            return retVal;
        }

        AuthorizationHeader authorizationHeader = new AuthorizationHeader(request);
        System.out.println("authorizationHeader: " + request.getHeader("authorization"));
        //log.log(Level.FINE,"AuthorizationHeader: header {0} token {1}",new Object[]{authorizationHeader.getHeader(), authorizationHeader.getToken()});

        // authenticate user
        if (!authorizationHeader.isNull()) {

            // log the user in using the token
            IWindowsIdentity windowsIdentity = null;
            try {
                windowsIdentity = providers.doFilter(request, response);
                if (windowsIdentity == null) {
                    if(authorizationHeader.getToken() != null) {
                        System.out.println("Tokens: " + authorizationHeader.getToken());
                        retVal = AuthStatus.SEND_CONTINUE;
                        return retVal;
                    } else {
                        log.log(Level.WARNING, "error getting windows user in user:");
                        retVal = AuthStatus.FAILURE;
                        return retVal;
                    }
                }
            } catch (Exception e) {
                log.log(Level.WARNING, "error loggin user: {0}", e.getMessage());
                sendUnauthorized(response, true);
                retVal = AuthStatus.FAILURE;
                return retVal;
            }

            try {
                if (!allowGuestLogin && windowsIdentity.isGuest()) {
                    log.log(Level.WARNING, "guest login disabled: {0}", windowsIdentity.getFqn());
                    sendUnauthorized(response, true);
                    return retVal;
                }

                log.log(Level.FINE, "logged in user: {0} ({1})", new Object[]{windowsIdentity.getFqn(), windowsIdentity.getSidString()});

                if (session == null) {
                    throw new AuthException("Expected HttpSession");
                }

                Subject subject = (Subject) session.getAttribute("javax.security.auth.subject");
                if (subject == null) {
                    subject = new Subject();
                }

                WindowsPrincipal windowsPrincipal = new WindowsPrincipal(windowsIdentity, principalFormat, roleFormat);

                log.log(Level.FINE, "roles: {0}", windowsPrincipal.getRolesString());
                subject.getPrincipals().add(windowsPrincipal);
                session.setAttribute("javax.security.auth.subject", subject);

                log.log(Level.INFO, "successfully logged in user: {0}", windowsIdentity.getFqn());

                request.getSession().setAttribute(PRINCIPAL_SESSION_KEY, windowsPrincipal);

                //NegotiateRequestWrapper requestWrapper = new NegotiateRequestWrapper(request, windowsPrincipal);
                //chain.doFilter(requestWrapper, response);
                retVal = AuthStatus.SUCCESS;
            } finally {
                windowsIdentity.dispose();
            }

            return retVal;
        }

        log.info("authorization required");
        retVal = sendUnauthorized(response, false);

        return retVal;
    }



    /**
     * Filter for a previously logged on user.
     * @param request
     *  HTTP request.
     * @param response
     *  HTTP response.
     * @param chain
     *  Filter chain.
     * @return
     *  True if a user already authenticated.
     * @throws ServletException
     * @throws IOException
     */
    private boolean doFilterPrincipal(HttpServletRequest request) {
        Principal principal = request.getUserPrincipal();
        if (principal == null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                principal = (Principal) session.getAttribute(PRINCIPAL_SESSION_KEY);
            }
        }

        if (principal == null) {
            // no principal in this request
            return false;
        }

        if (providers.isPrincipalException(request)) {
            // the providers signal to authenticate despite an existing principal, eg. NTLM post
            return false;
        }

        // user already authenticated
        if (principal instanceof WindowsPrincipal) {
            log.log(Level.SEVERE, "previously authenticated Windows user: {0}", principal.getName());
            /*WindowsPrincipal windowsPrincipal = (WindowsPrincipal) principal;
            NegotiateRequestWrapper requestWrapper = new NegotiateRequestWrapper(request, windowsPrincipal);
            chain.doFilter(requestWrapper, response);*/
        } else {
            log.log(Level.INFO, "previously authenticated user: {0}", principal.getName());
            //chain.doFilter(request, response);
        }

        return true;
    }


 
    /**
     * Set the principal format.
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
     * Set the principal format.
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

    private void setAuthenticationResult(GroupPrincipal principal, Subject client, MessageInfo messageInfo)
            throws IOException, UnsupportedCallbackException {
        if(principal == null) {
            handler.handle(new Callback[] {new CallerPrincipalCallback(client, principal)});
            messageInfo.getMap().put(AUTH_TYPE_INFO_KEY, MODULENAME);
        } else {
            CallerPrincipalCallback callerPrincipalCallback = new CallerPrincipalCallback(client, principal);
            GroupPrincipalCallback groupPrincipalCallback = new GroupPrincipalCallback(client,principal.getGroups());
            handler.handle(new Callback[]{callerPrincipalCallback, groupPrincipalCallback});
        }
    }
}
