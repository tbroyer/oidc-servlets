<%@ page import="net.ltgt.oidc.servlet.AbstractAuthorizationFilter" %>
<%@ page import="net.ltgt.oidc.servlet.UserPrincipal" %>
<%@ page import="net.ltgt.oidc.servlet.Utils" %>

<% if (request.getUserPrincipal() instanceof UserPrincipal) { %>
<p><%= ((UserPrincipal) request.getUserPrincipal()).getSessionInfo().userInfo().getName() %>
<% } else { %>
<form method=post action="/login">
<input type=hidden name="<%= Utils.RETURN_TO_PARAMETER_NAME %>" value="<%= Utils.getRequestUri(request) %>">
<button type=submit>Login</button>
</form>
<% } %>

<form method=post action=/logout>
<%-- Only include return-to parameter if linking to a public page --%>
<% if (!Boolean.TRUE.equals(request.getAttribute(AbstractAuthorizationFilter.IS_PRIVATE_REQUEST_ATTRIBUTE_NAME))) { %>
<input type=hidden name="<%= Utils.RETURN_TO_PARAMETER_NAME %>" value="<%= Utils.getRequestUri(request) %>">
<% } %>
<button type=submit>Logout</button>
</form>
