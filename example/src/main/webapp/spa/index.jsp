<%@ page session="false" %>
<%@ page import="net.ltgt.oidc.servlet.UserPrincipal" %>
<!doctype html>
<html>
<head>
    <title>SPA</title>
    <script>
    <%-- XXX: use proper JSON library --%>
    const user = {
        "name": "<%= ((UserPrincipal) request.getUserPrincipal()).getSessionInfo().getUserInfo().getName() %>",
        "admin": <%= request.isUserInRole("admin") %>
    };
    </script>
    <script defer src="/spa/spa.js"></script>
</head>
<body>
</body>
</html>
