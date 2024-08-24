package auth.kayodeo1.com;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.Date;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import smaApi.studentModel;

public class jwtUtil {
    private static final String SECRET_KEY = "LagosStateMinistryOfScienceAndTechnologyStudentsManagementApp";
    private static final long EXPIRATION_TIME = 86400000; // 1 day in milliseconds
    private static final String BLACKLIST_FILE = "jwt_blacklist.txt";

    @SuppressWarnings("deprecation")
    public static String createJWT(studentModel user) {
        return Jwts.builder()
                .setSubject(user.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .claim("email", user.getEmail())
                .claim("role", user.getRole())
                .claim("password", user.getPassword())
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY.getBytes())
                .compact();
    }

    public static Claims parseJWT(String jwt) throws JwtException {
        try {
            if (isBlacklisted(jwt)) {
                System.out.println("Token is blacklisted");
                return null;
            }
            return Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY.getBytes())
                    .build()
                    .parseClaimsJws(jwt)
                    .getBody();
        } catch (ExpiredJwtException e) {
            throw new JwtException("Token expired", e);
        } catch (SignatureException e) {
            throw new JwtException("Invalid signature", e);
            
        } catch (MalformedJwtException e) {
            throw new JwtException("Malformed JWT", e);
        } catch (JwtException e) {
            throw new JwtException("Error parsing JWT: " + e.getMessage(), e);
        }
    }

    public static void addToBlacklist(String token) {
        try {
            Files.write(Paths.get(BLACKLIST_FILE), (token + System.lineSeparator()).getBytes(), 
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            System.out.println("Token added to blacklist");
        } catch (IOException e) {
            System.err.println("Error writing to blacklist file: " + e.getMessage());
        }
    }

    public static boolean isBlacklisted(String token) {
        try {
            return Files.lines(Paths.get(BLACKLIST_FILE))
                        .anyMatch(line -> line.trim().equals(token));
        } catch (IOException e) {
            System.err.println("Error reading from blacklist file: " + e.getMessage());
            return false;
        }
    }
}