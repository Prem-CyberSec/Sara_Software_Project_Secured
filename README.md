# SecureDocs Application

SecureDocs is a secure internal document management system designed to protect sensitive organizational data. It features user authentication, role-based access control, secure document storage with encryption, and structured logging for auditability.

## Features

- User registration and authentication with JWT tokens
- Role-based access control (Admin, Manager, Viewer)
- Encrypted document upload and secure download
- Input validation and sanitization
- HTTPS enforcement and secure cookie handling
- Structured logging of security events and HTTP access
- Refresh token management and secure session handling

## Technologies Used

- Node.js with Express.js framework
- SQLite database
- JSON Web Tokens (JWT) for authentication
- bcrypt for password hashing
- AES-256-CBC encryption for documents
- Winston and Morgan for logging
- Other middlewares: express-validator, helmet, cors, express-fileupload

## Setup and Installation

1. Clone the repository:
```git clone <repo-url>
cd SecureDocs```

2. Install dependencies:
```npm install```

3. Create a `.env` file in the root directory with the following variables:
PORT=3000
JWT_SECRET=your_jwt_secret
JWT_ACCESS_EXPIRY=900 # Access token expiry in seconds (e.g., 900 = 15 minutes)
JWT_REFRESH_SECRET=your_refresh_secret
JWT_REFRESH_EXPIRY=604800 # Refresh token expiry in seconds (e.g., 604800 = 7 days)
DATABASE_PATH=./secureDocs.sqlite
NODE_ENV=development

4. Initialize the database (creates necessary tables and default roles):
node src/initDb.js

5. Start the application:
```npm start```

6. The API will be accessible at `http://localhost:3000/` (or the port you specified).

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register new user 
- `POST /api/auth/login` - User login to receive JWT access and refresh tokens 
- `POST /api/auth/token` - Refresh access token 
- `POST /api/auth/logout` - Logout and revoke refresh token 

### Document Management

- `GET /api/documents` - List accessible documents (role-based) 
- `POST /api/documents/upload` - Upload encrypted document (Admin and Manager only) 
- `GET /api/documents/download/:id` - Download and decrypt document 
- `DELETE /api/documents/:id` - Delete a document (owner or Admin only) 

## Security Features

- Passwords hashed securely with bcrypt 
- JWT-based stateless authentication with refresh token management 
- Role-based access control enforced on document and sensitive routes 
- AES-256-CBC encryption and decryption of all documents on disk 
- Input sanitization and validation preventing injection attacks 
- Enforced HTTPS with secure cookie flags for production environment 
- Structured logging with separation of HTTP access and security events

## Logging

- HTTP access logs captured by Morgan and stored separately 
- Application and security event logging with Winston, including user context and actions 
- Supports daily rotated log files for manageability 

## Known Limitations and Future Work

- Account lockout mechanism on repeated failed login attempts is pending 
- Centralized error-handling middleware for consistent client error responses requires completion 
- SSL/TLS certificates need configuration for production-grade HTTPS 
- Correlation IDs for log traceability are planned 
- Centralized log management and alerting integration is a future enhancement 

## License

This project is licensed under the MIT License.

---

*Developed as part of a secure software design and implementation project to showcase best practices in web application security.*
