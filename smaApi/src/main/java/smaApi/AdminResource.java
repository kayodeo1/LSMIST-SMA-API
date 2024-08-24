package smaApi;
import java.util.ArrayList;

import auth.kayodeo1.com.jwtUtil;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
@Path("/admin")
public class AdminResource {
	 private dbHelper helper = new dbHelper();
		jwtUtil jwt = new jwtUtil();

	 // READ (all students)
    @GET
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAllStudents(studentModel admin) throws Exception {
    	ArrayList<studentModel> students = helper.getAllStudent();
        System.out.println(students);
        if (admin.getRole().equals("super-admin")){
            return Response.ok(students).build();

        }return Response.status(Response.Status.UNAUTHORIZED).entity("Not Authorized to view").build();
    }
}
