package com.template.adapter.idp.util;

import org.sourceid.saml20.adapter.AuthnAdapterException;

public class LdapLookupException
  extends AuthnAdapterException
{
  private static final long serialVersionUID = 1L;
  
  public LdapLookupException(String message)
  {
    super(message);
  }
  
  public LdapLookupException(Throwable cause)
  {
    super(cause);
  }
  
  public LdapLookupException(String message, Throwable cause)
  {
    super(message, cause);
  }
}
