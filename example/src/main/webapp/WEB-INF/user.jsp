<%@ page import="net.ltgt.oidc.servlet.example.jetty.UserPrincipal" %>
<%@ page import="net.ltgt.oidc.servlet.example.jetty.Utils" %>

<% if (request.getUserPrincipal() instanceof UserPrincipal) { %>
<p><%= ((UserPrincipal) request.getUserPrincipal()).sessionInfo().userInfo().getName() %>
<% } else { %>
<form method=post action="/login">
<input type=hidden name="<%= Utils.RETURN_TO_PARAMETER_NAME %>" value="<%= Utils.getRequestUri(request) %>">
<button type=submit>Login</button>
</form>
<% } %>

<form method=post action=/logout>
<button type=submit>Logout</button>
</form>
