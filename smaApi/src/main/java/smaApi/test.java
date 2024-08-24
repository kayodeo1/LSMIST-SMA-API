/*
 * @author Kayode Ojo
 */
package smaApi;

import java.sql.SQLException;

public class test {

	public static void main(String[] args) throws SQLException {
		// TODO Auto-generated method stub
		dbHelper db = new dbHelper();
try {
	System.out.println(db.getAllStudent());
} catch (Exception e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
}

	}

}
