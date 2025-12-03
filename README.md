# AUTH_SERVER

OAuth2.0 Authorization Server Microservice built with Spring Boot.

## Features

- JWT-based authentication
- User registration and login
- Token refresh mechanism
- User info endpoint
- Role-based access control
- H2 database (development) / MySQL (production)

## REST API Endpoints

| Method | Endpoint | Description | Authentication |
|--------|----------|-------------|----------------|
| POST | `/auth/login` | Authenticate user and return tokens | Public |
| POST | `/auth/register` | Register a new user | Public |
| POST | `/auth/refresh` | Refresh access token | Public |
| POST | `/auth/logout` | Logout and invalidate tokens | Authenticated |
| GET | `/auth/userinfo` | Get current user information | Authenticated |

## Request/Response Examples

### Register
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "password123",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

### Login
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "password": "password123"
  }'
```

### Refresh Token
```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "your-refresh-token"
  }'
```

### Get User Info
```bash
curl -X GET http://localhost:8080/auth/userinfo \
  -H "Authorization: Bearer your-access-token"
```

### Logout
```bash
curl -X POST http://localhost:8080/auth/logout \
  -H "Authorization: Bearer your-access-token" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "your-refresh-token"
  }'
```

## Response Format

### Success Response
```json
{
  "success": true,
  "message": "Operation successful",
  "data": { ... },
  "timestamp": "2024-01-01T12:00:00"
}
```

### Error Response
```json
{
  "status": 400,
  "error": "Validation Error",
  "message": "Request validation failed",
  "path": "/auth/register",
  "timestamp": "2024-01-01T12:00:00",
  "fieldErrors": [
    {
      "field": "email",
      "message": "Email must be valid",
      "rejectedValue": "invalid-email"
    }
  ]
}
```

## Build & Run

### Prerequisites
- Java 17+
- Maven 3.6+

### Build
```bash
mvn clean package
```

### Run
```bash
mvn spring-boot:run
```

### Run Tests
```bash
mvn test
```

## Configuration

Key configuration properties in `application.properties`:

```properties
# JWT Configuration
jwt.secret=your-secret-key
jwt.access-token-expiration=3600000    # 1 hour
jwt.refresh-token-expiration=86400000  # 24 hours

# Database Configuration (for production)
spring.datasource.url=jdbc:mysql://localhost:3306/authdb
spring.datasource.username=your-username
spring.datasource.password=your-password
```

## Security

- Passwords are encrypted using BCrypt
- JWT tokens are signed with HMAC-SHA256
- Refresh tokens are stored in database and can be revoked
- Stateless session management
