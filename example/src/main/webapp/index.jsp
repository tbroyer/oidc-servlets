<%@ page session="false" %>
<!doctype html>
<html>
<head>
    <title>Home</title>
</head>
<body>
<h1>Home</h1>

<p><a href="/private/">Go to private</a></p>
<% if (request.isUserInRole("admin")) { %>
<p><a href="/admin/">Go to admin</a></p>
<% } %>

<%@ include file="/WEB-INF/user.jsp" %>

</body>
</html>
