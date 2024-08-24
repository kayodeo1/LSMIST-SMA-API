/*
 * @author Kayode Ojo
 */
package smaApi;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.concurrent.TimeUnit;


public class studentModel {
	private int userID;
	private String password;
	private String email;
	private String firstName;
	private String middleName;
	private String lastName;
	private String startDate="00/00/0000";
	private String endDate="00/00/0001";
	private String role="Student";
	private String institution;
	private String jwt;
	private String imgUrl;
	private String course;
	private double progress;
	private String status="unverified";
	private String duration;
	public String group;
	private String oldPassword;
	private String newPassword;
	public String getGroup() {
		return group;
	}
	public void setGroup(String group) {
		this.group = group;
	}
	public String getOldPassword() {
		return oldPassword;
	}
	public void setOldPassword(String oldPassword) {
		this.oldPassword = oldPassword;
	}
	public String getNewPassword() {
		return newPassword;
	}
	public void setNewPassword(String newPassword) {
		this.newPassword = newPassword;
	}
	public ArrayList<String> getGroupNotification() {
		return groupNotification;
	}
	public void setGroupNotification(ArrayList<String> groupNotification) {
		this.groupNotification = groupNotification;
	}
	public ArrayList<String> getGeneralNotification() {
		return generalNotification;
	}
	public void setGeneralNotification(ArrayList<String> generalNotification) {
		this.generalNotification = generalNotification;
	}

	public ArrayList<String> groupNotification;
	public ArrayList<String> generalNotification;



 	public studentModel() {


	}
	public String getFirstName() {
		return firstName;
	}
	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}
	public String getMiddleName() {
		return middleName;
	}
	public void setMiddleName(String middleName) {
		this.middleName = middleName;
	}
	public String getLastName() {
		return lastName;
	}
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	public String getStartDate() {
		return startDate;
	}
	public void setStartDate(String startDate) {
		this.startDate = startDate;
	}
	public String getEndDate() {
		return endDate;
	}
	public void setEndDate(String endDate) {
		this.endDate = endDate;
	}
	public String getImgUrl() {
		return imgUrl;
	}
	public void setImgUrl(String imgUrl) {
		this.imgUrl = imgUrl;
	}
	public String getCourse() {
		return course;
	}
	public void setCourse(String course) {
		this.course = course;
	}
	public double getProgress() {
		return progress;
	}
	public void setProgress(double progress) {
		this.progress = progress;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public String getDuration() {
		return duration;
	}
	public void setDuration(String duration) {
		this.duration = duration;
	}
	public String getJwt() {
		return jwt;
	}
	public void setJwt(String jwt) {
		this.jwt = jwt;
	}
	@Override
	public String toString() {
		return "studentModel [userID=" + userID + ", email=" + email + "], password="+ password ;
	}
	public int getUserID() {
		return userID;
	}
	public void setUserID(int userID) {
		this.userID = userID;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String username) {
		this.email = username;
	}
	public String getRole() {
		// TODO Auto-generated method stub
		return role;
	}
	public String getInstitution() {
		return institution;
	}
	public void setInstitution(String institution) {
		this.institution = institution;
	}
	public void setRole(String role) {
		this.role=role;
	}
public double getPercentComplete(String startDateStr, String endDateStr) {
    try {
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");
        Date startDate = sdf.parse(startDateStr);
        Date endDate = sdf.parse(endDateStr);
        Date currentDate = new Date();

        // Calculate the total number of days between the start and end dates
        long totalDays = TimeUnit.DAYS.convert(endDate.getTime() - startDate.getTime(), TimeUnit.MILLISECONDS);

        // Calculate the number of days between the start date and the current date
        long elapsedDays = TimeUnit.DAYS.convert(currentDate.getTime() - startDate.getTime(), TimeUnit.MILLISECONDS);

        // Calculate the percentage of completion
        double percentComplete = (double) elapsedDays / totalDays * 100;

        return percentComplete;
    } catch (ParseException e) {
        e.printStackTrace();
        return 0.0;
    }
}
}