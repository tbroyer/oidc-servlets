<%@ page import="net.ltgt.oidc.servlet.example.jetty.UserPrincipal" %>

<p><%= request.getUserPrincipal() instanceof UserPrincipal ? ((UserPrincipal) request.getUserPrincipal()).sessionInfo().userInfo().getName() : "[anonymous]" %>

<form method=post action=/logout>
<button type=submit>Logout</button>
</form>
