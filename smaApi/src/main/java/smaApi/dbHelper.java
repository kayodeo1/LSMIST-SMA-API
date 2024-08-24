package smaApi;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import auth.kayodeo1.com.KeyGenerator;
import auth.kayodeo1.com.PasswordCrypto;


public class dbHelper {
	connectDB db = new connectDB();
	ArrayList<studentModel> studentsList;
public ArrayList<String> getKeys() {
	ArrayList<String> keys  = new ArrayList();
	keys.add("LSMIST");
	keys.add("2024");
	keys.add("JaVa");
	keys.add("Mira");

	return keys;

}

	String key = KeyGenerator.generateKey(getKeys());

	public boolean addStudent(studentModel student) throws SQLException {
	    String query = "INSERT INTO smaStudents (email, password) VALUES (?, ?)";
	    try (Connection conn = db.connectDB("2377");
	         PreparedStatement pstmt = conn.prepareStatement(query)) {

	        if (!checkStudentExists(student.getEmail())) {
	            pstmt.setString(1, student.getEmail());
	            try {
					pstmt.setString(2, PasswordCrypto.encrypt(student.getPassword(), key));
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	            int rowsAffected = pstmt.executeUpdate();
	            return rowsAffected > 0;
	        }
	        return false;
	    }
	}

	public boolean deleteStudent(studentModel student) throws SQLException {
		// TODO update this query
		String query = "";
		if (checkStudentExists(student.getEmail())) {
			// TODO
			db.executeQuery(query, "2377");
			return true;

		}
		return false;
	}

	public boolean checkStudentExists(String email) throws SQLException {
	    String query = "SELECT 1 FROM smaStudents WHERE email = ?";
	    try (Connection conn = db.connectDB("2377");
	         PreparedStatement pstmt = conn.prepareStatement(query)) {

	        pstmt.setString(1, email);
	        try (ResultSet rs = pstmt.executeQuery()) {
	            return rs.next();
	        }
	    }
	}

	public ArrayList<studentModel> getAllStudent() throws Exception {
		studentsList = new ArrayList();
		ResultSet result = db.executeQuery("select * from smaStudents", "2377");
		while (result.next()) {
			studentModel res = new studentModel();
			res.setUserID(result.getInt("userID")); // userID is an integer
			res.setEmail(result.getString("email")); // email is a string
			res.setPassword(PasswordCrypto.encrypt(result.getString("password"), key)); // password is a string
			res.setFirstName(result.getString("firstName")); // firstName is a string
			res.setMiddleName(result.getString("middleName"));// middleName is a string
			res.setLastName(result.getString("lastName")); // lastName is a string
			res.setStartDate(result.getString("startDate")); // startDate is a date
			res.setEndDate(result.getString("endDate")); // endDate is a date
			res.setRole(result.getString("role")); // role is a string
			res.setInstitution(result.getString("institution")); // institution is a string
			res.setJwt(result.getString("jwt")); // jwt is a string
			res.setImgUrl(result.getString("imgUrl")); // imgUrl is a string
			res.setCourse(result.getString("course")); // course is a string
			if(res.getStartDate()!=null){// course is a string
				res.setProgress(
						res.getPercentComplete(res.getStartDate().replace("-", "/"), res.getEndDate().replace("-", "/"))); // progress
																															// is
																															// a
				}																										// is
																														// a
																														// decimal
			res.setStatus(result.getString("status")); // status is a string
			res.setDuration(result.getString("duration"));
			res.setGroup(result.getString("studentgroup"));
			studentsList.add(res);

		}
		return studentsList;

	}

	public studentModel getStudent(String email, String password) throws SQLException {

		if (checkStudentExists(email)) {
			return authenticate(email, password);
		}
		return null;
	}

	private studentModel authenticate(String email, String password) throws SQLException {
		// TODO Passwoed Encryption
		ResultSet result = db.executeQuery("select * from smaStudents where email = '" + email + "'", "2377");
		result.next();
		try {
			System.out.println(result.getString("password")+(PasswordCrypto.encrypt(password,key)));
			if (result.getString("password").equals(PasswordCrypto.encrypt(password,key))) {
				System.out.println("here22");
				studentModel res = new studentModel();
				res.setUserID(result.getInt("userID")); // userID is an integer
				res.setEmail(result.getString("email")); // email is a string
				try {
					res.setPassword(PasswordCrypto.encrypt(result.getString("password"), key));
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} // password is a string
				res.setFirstName(result.getString("firstName")); // firstName is a string
				res.setMiddleName(result.getString("middleName"));// middleName is a string
				res.setLastName(result.getString("lastName")); // lastName is a string
				res.setStartDate(result.getString("startDate")); // startDate is a date
				res.setEndDate(result.getString("endDate")); // endDate is a date
				res.setRole(result.getString("role")); // role is a string
				res.setInstitution(result.getString("institution")); // institution is a string
				res.setImgUrl(result.getString("imgUrl")); // imgUrl is a string
				res.setCourse(result.getString("course"));
				if(res.getStartDate()!=null){// course is a string
				res.setProgress(
						res.getPercentComplete(res.getStartDate().replace("-", "/"), res.getEndDate().replace("-", "/"))); // progress
																															// is
																															// a
				}																									// decimal
				res.setStatus(result.getString("status")); // status is a string
				res.setDuration(result.getString("duration"));
				res.setGroup(result.getString("studentgroup"));
				return res;
			} else {
				System.out.println("wrong pword");
				return null;
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public boolean updateStudent(studentModel s) throws SQLException {
		StringBuilder queryBuilder = new StringBuilder("UPDATE smaStudents SET ");
		List<String> updateFields = new ArrayList<>();
		List<Object> parameters = new ArrayList<>();

		if (s.getFirstName() != null) {
			updateFields.add("firstName = ?");
			parameters.add(s.getFirstName());
		}
		if (s.getMiddleName() != null) {
			updateFields.add("middleName = ?");
			parameters.add(s.getMiddleName());
		}
		if (s.getLastName() != null) {
			updateFields.add("lastName = ?");
			parameters.add(s.getLastName());
		}
		if (s.getStartDate() != null) {
			updateFields.add("startDate = ?");
			parameters.add(s.getStartDate());
		}
		if (s.getEndDate() != null) {
			updateFields.add("endDate = ?");
			parameters.add(s.getEndDate());
		}

		if (s.getInstitution() != null) {
			updateFields.add("institution = ?");
			parameters.add(s.getInstitution());
		}

		if (s.getImgUrl() != null) {
			updateFields.add("imgUrl = ?");
			parameters.add(s.getImgUrl());
		}
		if (s.getCourse() != null) {
			updateFields.add("course = ?");
			parameters.add(s.getCourse());
		}

		if (s.getDuration() != null) {
			updateFields.add("duration = ?");
			parameters.add(s.getDuration());
		}

		if (updateFields.isEmpty()) {
			return false; // No fields to update
		}

		queryBuilder.append(String.join(", ", updateFields));
		queryBuilder.append(" WHERE email = ?");

		try (PreparedStatement stmt = db.connectDB("2377").prepareStatement(queryBuilder.toString())) {
			for (int i = 0; i < parameters.size(); i++) {
				stmt.setObject(i + 1, parameters.get(i));
			}
			stmt.setString(parameters.size() + 1, s.getEmail());

			int rowsAffected = stmt.executeUpdate();

			// Update studentgroup separately if it's provided
			if (s.getGroup() != null) {
				try (PreparedStatement groupStmt = db.connectDB("2377")
						.prepareStatement("UPDATE smaStudents SET studentgroup = ? WHERE email = ?")) {
					groupStmt.setString(1, s.getGroup());
					groupStmt.setString(2, s.getEmail());
					groupStmt.executeUpdate();
				}
			}

			return rowsAffected > 0;
		} catch (SQLException e) {
			e.printStackTrace();
			return false;
		}
	}

	public boolean updatePassword(String email, String oldPassword, String newPassword) throws SQLException {
	    String selectQuery = "SELECT password FROM smaStudents WHERE email = ?";
	    String updateQuery = "UPDATE smaStudents SET password = ? WHERE email = ?";

	    try (Connection conn = db.connectDB("2377");
	         PreparedStatement selectStmt = conn.prepareStatement(selectQuery);
	         PreparedStatement updateStmt = conn.prepareStatement(updateQuery)) {

	        // Verify old password
	        selectStmt.setString(1, email);
	        try (ResultSet rs = selectStmt.executeQuery()) {
	            if (rs.next()) {
	                String storedPassword = rs.getString("password");
	                try {
	                    storedPassword = PasswordCrypto.decrypt(storedPassword, key);
	                    if (!verifyPassword(oldPassword, storedPassword)) {
	                        return false; // Old password doesn't match
	                    }
	                } catch (Exception e) {
	                    throw new SQLException("Error decrypting password", e);
	                }
	            } else {
	                return false; // User not found
	            }
	        }

	        // Update with new password
	        String hashedNewPassword = hashPassword(newPassword);
	        updateStmt.setString(1, hashedNewPassword);
	        updateStmt.setString(2, email);

	        int rowsAffected = updateStmt.executeUpdate();
	        return rowsAffected > 0;
	    }
	}

	private boolean verifyPassword(String inputPassword, String storedPassword) {
	    return inputPassword.equals(storedPassword); // Note: This is not a secure way to verify passwords
	}

	private String hashPassword(String password) {
	    try {
	        return PasswordCrypto.encrypt(password, key);
	    } catch (Exception e) {
	        throw new RuntimeException("Error hashing password", e);
	    }
	}
}