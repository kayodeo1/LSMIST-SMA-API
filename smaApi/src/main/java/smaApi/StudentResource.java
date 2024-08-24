package smaApi;

import java.sql.SQLException;
import java.util.ArrayList;

import auth.kayodeo1.com.KeyGenerator;
import auth.kayodeo1.com.PasswordCrypto;
import auth.kayodeo1.com.auth;
import auth.kayodeo1.com.jwtUtil;
import auth.kayodeo1.com.mailSender;
import auth.kayodeo1.com.validator;
import io.jsonwebtoken.Claims;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/students")
public class StudentResource {
	public ArrayList<String> getKeys() {
		ArrayList<String> keys  = new ArrayList();
		keys.add("LSMIST");
		keys.add("2024");
		keys.add("JaVa");
		keys.add("Mira");

		return keys;

	}

		String key = KeyGenerator.generateKey(getKeys());

	private dbHelper helper = new dbHelper();
	auth authenticate = new auth();
	jwtUtil jwt = new jwtUtil();

	// SEND EMAIL WITH VERIFICATION CODE
	@Path("/authenticate")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.TEXT_PLAIN)
	public Response authenticate(studentModel student) throws SQLException {
		// Retrieve recipient email and other necessary details
		String recipientEmail = student.getEmail();
		String appPassword = "Olecram2.";
		String email = "ojokayode566@outlook.com";
		if (helper.checkStudentExists(recipientEmail)) {
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(
					"Failed to send verification email: " + "Student already exist with email:" + recipientEmail)
					.build();
		}
		// Initialize mailSender object
		mailSender msg = new mailSender(email, appPassword);
		String subject = "Verification Mail from SMA Ministry of Science and Technology";

		try {
			// Generate authentication code and HTML content
			int code = authenticate.genAuthInstance(recipientEmail).getCode();
			System.out.println("fine here so far");
			String htmlContent = auth.generateHtmlContent(String.valueOf(code));

			// Send the email
			msg.sendEmail(recipientEmail, subject, htmlContent);

			// Return success response
			return Response.ok("Verification email sent successfully.").build();
		} catch (Exception e) {
			// Log the exception
			e.printStackTrace();

			// Return error response
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
					.entity("Failed to send verification email: " + e.getMessage()).build();
		}
	}

	// READ (single student)
	@GET
	@Produces(MediaType.APPLICATION_JSON)
	public Response getStudent(@QueryParam("jwt") String token) throws Exception {
	    Claims jwtValues = jwtUtil.parseJWT(token);
	    if (jwtValues==null) {
	    	return Response.status(Response.Status.BAD_REQUEST).entity("Expired or invalid token").build();
	    }
	    String email = jwtValues.get("email").toString();

	    studentModel student;
	    try {
	        String decryptedPassword = PasswordCrypto.decrypt(PasswordCrypto.decrypt(jwtValues.get("password").toString(), key), key);
	        System.out.println(decryptedPassword);
	        student = helper.getStudent(email, decryptedPassword);
	        return Response.ok(student).build();
	    } catch (SQLException e) {
	        e.printStackTrace();
	        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Database error occurred").build();
	    } catch (Exception e) {
	        e.printStackTrace();
	        return Response.status(Response.Status.BAD_REQUEST).entity("Invalid JWT or decryption error").build();
	    }
	}
	// UPDATE
	@PUT
	@Path("/{userID}")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response updateStudent(studentModel student) throws SQLException {
		Claims jwtValues = jwtUtil.parseJWT(student.getJwt());
		if (jwtValues==null) {
			return Response.status(Response.Status.BAD_REQUEST).entity("Can not update:JWT token expired , try to login again " + student.getEmail())
					.build();
	}

		System.out.println(jwtValues);
		if (jwtValues.get("email").equals(student.getEmail())) {
			if (helper.updateStudent(student)) {
		        String decryptedPassword;
				try {
					decryptedPassword = PasswordCrypto.decrypt(PasswordCrypto.decrypt(jwtValues.get("password").toString(), key), key);
					studentModel updatedStudent = helper.getStudent(jwtValues.get("email").toString(),
							decryptedPassword);
					return Response.ok(updatedStudent).build();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			} else {
				return Response.status(Response.Status.BAD_REQUEST)
						.entity("No fields to update or update failed for Student: " + student.getEmail()).build();
			}
		}

		return Response.status(Response.Status.UNAUTHORIZED).entity("Unauthorized to update this student").build();
	}

	// generate token DONE
	@GET
	@Path("/login")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response login(studentModel student) {
		try {
			studentModel Student = helper.getStudent(student.getEmail(), student.getPassword());
			if (Student != null) {
				Student.setJwt(jwtUtil.createJWT(Student));
				return Response.ok(Student).build();
			} else {
				return Response.status(Response.Status.NOT_FOUND).entity("Student not found or incorrect password")
						.build();
			}
		} catch (SQLException e) {
			e.printStackTrace();
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error retrieving student").build();
		}
	}

	@Path("/validate")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response validate(validator student) throws SQLException {
		String recipentEmail = student.getEmail();
		int code = Integer.parseInt(student.getCode());
		if (authenticate.validateAuthInstance(recipentEmail, code)) {
			studentModel Student = new studentModel();
			Student.setEmail(recipentEmail);
			Student.setPassword(student.getPassword());
			Student.setStatus("validated");
			helper.addStudent(Student);
			return login(Student);
		}
		return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
				.entity("Failed to verify: " + "Try entering code again").build();

	}

	@PUT
	@Path("/password")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response changePassword(studentModel student) {
		
		Claims jwtValues = jwtUtil.parseJWT(student.getJwt());
			if (jwtValues==null) {
				return Response.status(Response.Status.BAD_REQUEST).entity("Failed to change password:JWT token expired , try to login again " + student.getEmail())
						.build();
		}
		if (jwtValues.get("email").equals(student.getEmail())) {
			try {
				if (helper.updatePassword(student.getEmail(), student.getOldPassword(), student.getNewPassword())) {
					jwtUtil.addToBlacklist(student.getJwt());
					return Response.ok("password changed but jwt aleady invalidated so you need to login again to create new token , youre not logged out yet tho").build();
				}

			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return Response.status(Response.Status.BAD_REQUEST).entity("Failed to change password: " + student.getEmail())
				.build();

	}

	@Path("/logout")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response logout(studentModel student) {
		try {
	        String token = student.getJwt();
	        // Add the token to the blacklist
	        jwtUtil.addToBlacklist(token);

	        return Response.ok("{\"message\": \"Logout successful\"}").build();
	    } catch (Exception e) {
	        e.printStackTrace();
	        return Response.status(Response.Status.BAD_REQUEST)
	                .entity("{\"error\": \"Invalid token or logout failed\"}").build();
	    }
	}
}
