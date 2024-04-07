<%@ page session="false" %>
<!doctype html>
<html>
<head>
    <title>Private</title>
</head>
<body>
<h1>Private</h1>

<p><a href="/">Go to home</a></p>
<% if (request.isUserInRole("admin")) { %>
<p><a href="/admin/">Go to admin</a></p>
<% } %>

<%@ include file="/WEB-INF/user.jsp" %>

</body>
</html>
