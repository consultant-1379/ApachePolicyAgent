<%-- 
    Document   : isAlive
    Created on : 10-Jan-2014, 14:22:42
    Author     : ealemca
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>

<head>
    <title>OpenAM</title>
</head>

<body>

<%
	/**
	 * Mock up of actual OpenAM "isAlive.jsp" server check. This
	 * will be used in unit testing the Policy Agent install
	 * procedure
	 */
    Object attributes = null;

	if (attributes != null) {
        /**
         * Identity Server or directory is down, have failure message here
          * or throw an exception. This currently throws an exception
         * which will cause web server to return error code of 500,
         * to return an error message, comment the "throw" line
         */
        out.println("<h1>Server is DOWN</h1>");
        throw (new ServletException("directory is down"));
    } else {
        /**
         * Identity Server is alive, have success message below
         */
        out.println("<h1>Server is ALIVE: </h1>");
    }
%>

</body>

</html>
