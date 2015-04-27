package com.template.adapter.idp;

import java.io.IOException;
import java.lang.Object;
import java.lang.String;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.common.ResponseTemplateRenderer;
import org.sourceid.common.Util;
import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.CheckBoxFieldDescriptor;
import org.sourceid.saml20.adapter.gui.LdapDatastoreFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.IntegerValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;

import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthnAdapterDescriptor;
import org.sourceid.saml20.domain.SpConnection;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;
import org.sourceid.saml20.metadata.MetaDataFactory;
import org.sourceid.saml20.metadata.partner.MetadataDirectory;

import com.pingidentity.common.security.InputValidator;
import com.pingidentity.common.security.UsernameRule;
import com.pingidentity.common.util.HTMLEncoder;
import com.pingidentity.sdk.AuthnAdapterResponse;
import com.pingidentity.sdk.IdpAuthenticationAdapterV2;
import com.template.adapter.idp.util.DefaultProperties;
import com.template.adapter.idp.util.LDAPUtil;
import com.template.adapter.idp.util.LdapAttributeFinder;
import com.template.adapter.idp.util.LdapLookupException;



//LDAP
import javax.naming.directory.Attributes;

/**
 * <p>
 * This class is an example of an IdP authentication adapter that uses a
 * velocity HTML form template to display a form to the user. The username is
 * provided by a previous adapter and can not be changed. If not username
 * provided the authn will fail with an exception.
 * </p>
 */
public class TemplateAdapter implements IdpAuthenticationAdapterV2 {

    private static final String ADAPTER_NAME = "Template Adapter";
	private static final String ADAPTER_VERSION = "1.0";
    private final Log log = LogFactory.getLog(this.getClass());

    //LDAP
    private boolean queryDirectory;
    private static final LDAPUtil ldapUtil = new LDAPUtil();
    private String ldapDataSourceAlias;
    private LdapAttributeFinder ldapAttributeFinder;
    private DefaultProperties defaultProperties;
    
    //Session
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String REQUEST_TOKEN_SESSION_KEY = "RequestToken";

    //Templates
    public static String FAILED_MESSAGE = "Failed - Please try again";

    public static final String FIELD_LOGIN_TEMPLATE_NAME = "Login Template";
    public static final String DEFAULT_LOGIN_TEMPLATE_NAME = "html.form.blank.template.html";
    public static final String DESC_LOGIN_TEMPLATE_NAME = "HTML template (in <pf_home>/server/default/conf/template) to render for login.  The default value is " + DEFAULT_LOGIN_TEMPLATE_NAME + ".";

    public static final String FIELD_FAILURE_TEMPLATE_NAME = "Failure Template";
    public static final String DEFAULT_FAILURE_TEMPLATE_NAME = "html.form.blank-failure.template.html";
    public static final String DESC_FAILURE_TEMPLATE_NAME = "HTML template (in <pf_home>/server/default/conf/template) to render in the case that authentication fails. The default value is " + DEFAULT_FAILURE_TEMPLATE_NAME + ".";

    public static final String ATTR_NAME_AUTH_STATUS = "authentication_status";
    public static final String ATTR_NAME_USER_NAME = "username";
    public static final String ATTR_NAME_ERROR = "error_message";

    // HTML form field names
    private static final String FORM_FIELD_STATE = "state";
    private static final String FORM_FIELD_ARG1 = "input1";
    private static final String FORM_FIELD_REQUEST_ID = "request_id";

    private final IdpAuthnAdapterDescriptor descriptor;
    private String htmlTemplate;
    private String htmlFailureTemplate;
    private boolean allowOptOut = false;
    private boolean allowNonInteractive = false;

    public TemplateAdapter() {

        AdapterConfigurationGuiDescriptor guiDescriptor = new AdapterConfigurationGuiDescriptor();

        //Template Handling
        TextFieldDescriptor loginTemplateName = new TextFieldDescriptor(FIELD_LOGIN_TEMPLATE_NAME, DESC_LOGIN_TEMPLATE_NAME);
        loginTemplateName.addValidator(new RequiredFieldValidator());
        loginTemplateName.setDefaultValue(DEFAULT_LOGIN_TEMPLATE_NAME);
        guiDescriptor.addField(loginTemplateName);

        TextFieldDescriptor failureTemplateName = new TextFieldDescriptor(FIELD_FAILURE_TEMPLATE_NAME, DESC_FAILURE_TEMPLATE_NAME);
        failureTemplateName.addValidator(new RequiredFieldValidator());
        failureTemplateName.setDefaultValue(DEFAULT_FAILURE_TEMPLATE_NAME);
        guiDescriptor.addField(failureTemplateName);

        //Configuration File Settings location
        TextFieldDescriptor baseFileLocationField = new TextFieldDescriptor("Configuration File Location", "The directory location for configuration files.");
        guiDescriptor.addAdvancedField(baseFileLocationField);

        //LDAP
        LdapDatastoreFieldDescriptor ldapDatastoreFieldDescriptor = new LdapDatastoreFieldDescriptor("LDAP Data source", "The LDAP data source used for retrieving additional user attributes");
        guiDescriptor.addAdvancedField(ldapDatastoreFieldDescriptor);
        
        CheckBoxFieldDescriptor queryDirectoryField = new CheckBoxFieldDescriptor("Query Directory", "Query directory for every PingID authentication.");
        queryDirectoryField.setDefaultValue(false);
        guiDescriptor.addAdvancedField(queryDirectoryField);
        
        TextFieldDescriptor baseDomainField = new TextFieldDescriptor("Base Domain", "The base domain for attribute retrieval.");
        guiDescriptor.addAdvancedField(baseDomainField);
        
        TextFieldDescriptor ldapFilerField = new TextFieldDescriptor("Filter", "The filter for attribute retrieval. ${username} may be used to refer to the subject. Example: sAMAccountName=${username}");
        guiDescriptor.addAdvancedField(ldapFilerField);
        
        TextFieldDescriptor fnameAttributeField = new TextFieldDescriptor("fname attribute", "The ldap attribute for fname.");
        guiDescriptor.addAdvancedField(fnameAttributeField);
        
        //Other
        Set<String> attrNames = new HashSet<String>();
        attrNames.add(ATTR_NAME_USER_NAME);
       
        descriptor = new IdpAuthnAdapterDescriptor(this, this.ADAPTER_NAME, attrNames, false, guiDescriptor, false, this.ADAPTER_VERSION);
    }

    private void debug_message(String message) {
        log.debug(message);
        System.out.println("**********************************");
        System.out.println(message);
    }

    public IdpAuthnAdapterDescriptor getAdapterDescriptor() {
        return descriptor;
    }

    @SuppressWarnings("rawtypes")
    public boolean logoutAuthN(Map authnIdentifiers, HttpServletRequest req,
                               HttpServletResponse resp, String resumePath)
    throws AuthnAdapterException, IOException {

        return true;
    }

    public void configure(Configuration configuration) {

        debug_message("configure");

        htmlTemplate = configuration.getFieldValue(FIELD_LOGIN_TEMPLATE_NAME);
        htmlFailureTemplate = configuration.getFieldValue(FIELD_FAILURE_TEMPLATE_NAME);

        this.ldapDataSourceAlias = configuration.getAdvancedFields().getFieldValue("LDAP Data source");
        //this.ldapAttributeFinder = new LdapAttributeFinder(this.log, configuration, this.nameValidator, this.emailValidator, ldapDataSourceAccessor, ldapUtil);
        this.queryDirectory = configuration.getAdvancedFields().getBooleanFieldValue("Query Directory");
        
    }

    public Map<String, Object> getAdapterInfo() {
        return null;
    }

    private static String setRequestToken(HttpServletRequest req) {
        String requestToken = new BigInteger(20 * 8, secureRandom).toString(32);
        req.getSession().setAttribute(REQUEST_TOKEN_SESSION_KEY, requestToken);
        return requestToken;
    }

    @SuppressWarnings( { "rawtypes", "unchecked" })
    public AuthnAdapterResponse lookupAuthN(HttpServletRequest req,
                                            HttpServletResponse resp, Map<String, Object> inParameters)
    throws AuthnAdapterException, IOException {

        debug_message(ADAPTER_NAME + " lookupAuthN");
        AuthnAdapterResponse authnAdapterResponse = new AuthnAdapterResponse();
        authnAdapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.IN_PROGRESS);

        HashMap<String, Object> adapterAttributes = new HashMap<String, Object>();

        Map<String, AttributeValue> chainedAttributes = (Map<String, AttributeValue>) inParameters.get(
                IN_PARAMETER_NAME_CHAINED_ATTRIBUTES);        
        
        if (MapUtils.isNotEmpty(chainedAttributes)) {
            log.info("chainedAttributes");
            for (Map.Entry<String, AttributeValue> e : chainedAttributes.entrySet()) {
                StringBuffer sb = new StringBuffer();
                sb.append(" " + e.getKey());
                if ((e.getValue() != null) && (e.getValue() instanceof AttributeValue))
                    sb.append(" : " + e.getValue().toString());
                log.info(sb.toString());
            }
        }

        log.info("inParameters:");
        for (Map.Entry<String, Object> e : inParameters.entrySet()) {
            StringBuffer sb = new StringBuffer();
            sb.append(" " + e.getKey());
            if (e.getValue() != null)
                sb.append(" : " + e.getValue().toString());
            log.info(sb.toString());
        }
        
        log.info("request Parameters:");
        for (Map.Entry<String, String[]> reqParam : req.getParameterMap().entrySet()) {
            log.info(" " + reqParam.getKey() + " : " + reqParam.getValue()[0].toString());
        }

        // make sure we're in an interactive session
        AuthnPolicy authnPolicy = (AuthnPolicy) inParameters.get(IN_PARAMETER_NAME_AUTHN_POLICY);
        if (!authnPolicy.allowUserInteraction()) {
            if(allowNonInteractive) {
                authnAdapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.SUCCESS);
            } else {
                authnAdapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
            }
            return authnAdapterResponse;
        }

        String resumePath = inParameters.get(IN_PARAMETER_NAME_RESUME_PATH).toString();
        String partnerEntityId = inParameters.get(IN_PARAMETER_NAME_PARTNER_ENTITYID).toString();

        String userName = chainedAttributes.get("username").getValue();
        
        String responseTemplate = htmlTemplate;
        Map<String, Object> responseParams = new HashMap<String, Object>();
        responseParams.put("url", resumePath);

        String requestToken = (String)req.getSession().getAttribute(REQUEST_TOKEN_SESSION_KEY);
        if (requestToken != null) {
            // validate postback
            debug_message("Session requestToken = " + requestToken);
            req.getSession().removeAttribute(REQUEST_TOKEN_SESSION_KEY);
            
            // success is the ultimate result of second-factor authentication
            if(req.getSession().getAttribute("success").equals("true")) {
                responseTemplate = null;
                authnAdapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.SUCCESS);
            } else {
            	responseTemplate = htmlFailureTemplate;
                authnAdapterResponse.setAuthnStatus(AuthnAdapterResponse.AUTHN_STATUS.FAILURE);
            }
        } else {
            debug_message("First call");

            //Lookup LDAP
            Attributes ldapAttributes = null;
            this.log.debug("Performing LDAP query for user attributes.");
            try
            {
            	ldapAttributes = this.ldapAttributeFinder.getUsersAttributes(userName, this.defaultProperties.getLdapSearchScope(), this.defaultProperties.getLdapCountLimit());
            }
            catch (LdapLookupException e)
            {
              this.log.warn("Query for attributes failed: " + e.getMessage());
            }

            setRequestToken(req);           
            req.getSession().setAttribute("success", "true");            
        }

        if (responseTemplate != null) {
        	ResponseTemplateRenderer renderer = ResponseTemplateRenderer.getInstance();
            renderer.render(req, resp, responseTemplate, responseParams);
        }

        adapterAttributes.put(ATTR_NAME_USER_NAME, userName);
        authnAdapterResponse.setAttributeMap(adapterAttributes);
        return authnAdapterResponse;


    }

    /**
     * This method is deprecated. It is not called when
     * IdpAuthenticationAdapterV2 is implemented. It is replaced by
     * {@link #lookupAuthN(HttpServletRequest, HttpServletResponse, Map)}
     *
     * @deprecated
     */
    @SuppressWarnings(value = { "rawtypes" })
    public Map lookupAuthN(HttpServletRequest req, HttpServletResponse resp,
                           String partnerSpEntityId, AuthnPolicy authnPolicy, String resumePath)
    throws AuthnAdapterException, IOException {

        throw new UnsupportedOperationException();
    }

}
