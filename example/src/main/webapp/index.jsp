<%@ page session="false" %>
<%@ page import="net.ltgt.oidc.servlet.example.jetty.UserPrincipal" %>
<!doctype html>
<html>
<head>
    <title>Home</title>
</head>
<body>
<h1>Home</h1>

<p><%= ((UserPrincipal) request.getUserPrincipal()).sessionInfo().userInfo().getName() %></p>

<form method=post action=/logout>
<button type=submit>Logout</button>
</form>

</body>
</html>
