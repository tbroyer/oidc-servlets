<%@ page session="false" %>
<!doctype html>
<html>
<head>
    <title>Home</title>
</head>
<body>
<h1>Home</h1>

<ul>
<li><a href="/other.jsp">Go to other page</a>
<li>SPA
    <ul>
    <li><a href="/spa/">Go to SPA</a>
    <li><a href="/spa/deeplink">SPA deep link</a>
    </ul>
<li><a href="/private/">Go to private</a>
<% if (request.isUserInRole("admin")) { %>
<li><a href="/admin/">Go to admin</a>
<% } %>
</ul>

<%@ include file="/WEB-INF/user.jsp" %>

</body>
</html>
