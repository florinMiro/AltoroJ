/**
 This application is for demonstration use only. It contains known application security
vulnerabilities that were created expressly for demonstrating the functionality of
application security testing tools. These vulnerabilities may present risks to the
technical environment in which the application is installed. You must delete and
uninstall this demonstration application upon completion of the demonstration for
which it is intended. 

IBM DISCLAIMS ALL LIABILITY OF ANY KIND RESULTING FROM YOUR USE OF THE APPLICATION
OR YOUR FAILURE TO DELETE THE APPLICATION FROM YOUR ENVIRONMENT UPON COMPLETION OF
A DEMONSTRATION. IT IS YOUR RESPONSIBILITY TO DETERMINE IF THE PROGRAM IS APPROPRIATE
OR SAFE FOR YOUR TECHNICAL ENVIRONMENT. NEVER INSTALL THE APPLICATION IN A PRODUCTION
ENVIRONMENT. YOU ACKNOWLEDGE AND ACCEPT ALL RISKS ASSOCIATED WITH THE USE OF THE APPLICATION.

IBM AltoroJ
(c) Copyright IBM Corp. 2008, 2013 All Rights Reserved.
 */
package com.ibm.security.appscan.altoromutual.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ibm.security.appscan.altoromutual.util.DBUtil;

/**
 * This servlet handles site admin operations
 * @author Alexei
 */
public class AdminServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String message = null;
		
		//add account
		if (request.getRequestURL().toString().endsWith("addAccount")){
			String username = request.getParameter("username");
			String acctType = request.getParameter("accttypes");
			if (username == null || acctType == null || username.trim().length() == 0 || acctType.trim().length() == 0)
				message = "An error has occurred. Please try again later.";
			else {
				String error = DBUtil.addAccount(username, acctType);
				if (error != null)
					message = error;
			}
		}
		
		//add user
		else if (request.getRequestURL().toString().endsWith("addUser")){
			String firstname = request.getParameter("firstname");
			String lastname = request.getParameter("lastname");
			String username = request.getParameter("username");
			String password1 = request.getParameter("password1");
			String password2 = request.getParameter("password2");
			if (username == null || username.trim().length() == 0
				|| password1 == null || password1.trim().length() == 0
				|| password2 == null || password2.trim().length() == 0)
				message = "An error has occurred. Please try again later.";
			
			if (firstname == null){
				firstname = "";
			}
			
			if (lastname == null){
				lastname = "";
			}
			
			if (message == null && !password1.equals(password2)){
				message = "Entered passwords did not match.";
			}
			
			if (message == null){
				String error = DBUtil.addUser(username, password1, firstname, lastname);
				
				if (error != null)
					message = error;
			}
			
		}
		
		//change password
		else if (request.getRequestURL().toString().endsWith("changePassword")){
			String username = request.getParameter("username");
			String password1 = request.getParameter("password1");
			String password2 = request.getParameter("password2");
			if (username == null || username.trim().length() == 0
					|| password1 == null || password1.trim().length() == 0
					|| password2 == null || password2.trim().length() == 0)
					message = "An error has occurred. Please try again later.";
			
			if (message == null && !password1.equals(password2)){
				message = "Entered passwords did not match.";
			}
			
			if (message == null) {
				String error = DBUtil.changePassword(username, password1);
				
				if (error != null)
					message = error;
			}
		}
		else {
			message = "An error has occurred. Please try again later.";	
		}
		
		if (message != null)
			message = "Error: " + message;
		else
			message = "Requested operation has completed successfully.";
		
		request.getSession().setAttribute("message", message);
		response.sendRedirect("admin.jsp");
		return ;
	}

	public static void function1(File destDir, InputStream inputStream) throws IOException {
		TarArchiveInputStream tin = new TarArchiveInputStream(inputStream);
		TarArchiveEntry tarEntry = null;
  
		while ((tarEntry = tin.getNextTarEntry()) != null) {
			File destEntry = new File(destDir, tarEntry.getName());
			File parent = destEntry.getParentFile();
  
			if (!parent.exists()) {
				parent.mkdirs();
			}
  
			if (tarEntry.isDirectory()) {
				destEntry.mkdirs();
			} else {
				FileOutputStream fout = new FileOutputStream(destEntry);
		   fout.close();
			}
		}
	   
		tin.close();
	}
	public static void function2(HttpServletRequest request, HttpServletResponse response)
	throws ServletException, IOException {
   
	try {
		String callback = request.getParameter("callback");
		response.setCharacterEncoding("UTF-8");
		response.setHeader("Content-Type", callback == null ? "application/json" : "text/javascript");
	   
		PrintWriter writer = response.getWriter();
		if (callback != null) {
			writer.write(callback);
			writer.write("(");
		}          
}

public static boolean function3(String user) throws SQLException{
	if (user == null || user.trim().length() == 0 || password.trim().length() == 0)
		return false;
   
	String password = request.getParameter("passwd");
Connection connection = getConnection();
	Statement statement = connection.createStatement();
   
	ResultSet resultSet =statement.executeQuery("SELECT COUNT(*)FROM PEOPLE WHERE USER_ID = '"+ user +"' AND PASSWORD='" + password + "'"); /* BAD - user input should always be sanitized */
   
	if (resultSet.next()){
	   
			if (resultSet.getInt(1) > 0)
				return true;
	}
	return false;
}


}
