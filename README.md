# Library Access Control System

A secure Flask web application implementing Role-Based Access Control (RBAC) for a university library system. Built as part of CMPE 132 Information Security coursework.

## 🔐 Security Features

- **Password Security**: bcrypt hashing with salt for secure password storage
- **Role-Based Access Control (RBAC)**: Three-tier permission system
- **Authentication**: Flask-Login session management
- **Authorization**: Access Control Lists (ACLs) for granular permissions
- **SQL Injection Protection**: SQLAlchemy ORM with parameterized queries
- **User Provisioning**: Approval workflow for elevated privileges

## 🏗️ System Architecture

### User Roles & Permissions

| Role | Permissions |
|------|-------------|
| **Student** | Borrow books, Return books, View catalog, Access library resources |
| **Faculty** | All student permissions + Reserve books |
| **Librarian** | All permissions + Manage catalog, Approve roles, Delete users |

### Database Schema
- **User Table**: ID, username, hashed password, role, approval status
- **Approval Table**: Manages pending role approvals
- **Foreign Key Relationships**: Links approvers to approved users

## 🚀 Technologies Used

- **Backend**: Python, Flask
- **Database**: SQLite with SQLAlchemy ORM
- **Security**: Flask-Bcrypt, Flask-Login
- **Forms**: Flask-WTF with validation
- **Frontend**: HTML templates with Jinja2

## 📁 Project Structure

```
library-access-control/
├── app.py                 # Main Flask application
├── templates/
│   ├── home.html         # Landing page
│   ├── login.html        # Authentication form
│   ├── register.html     # User registration
│   ├── dashboard.html    # Role-based dashboard
│   └── approve_roles.html # Admin approval interface
└── database.db          # SQLite database (auto-generated)
```

## 🔧 Installation & Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/library-access-control.git
   cd library-access-control
   ```

2. **Install dependencies**
   ```bash
   pip install flask flask-sqlalchemy flask-login flask-wtf flask-bcrypt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Access the application**
   - Open browser to `http://localhost:5000`
   - Default admin credentials: `admin` / `admin`

## 🎯 Key Features Demonstrated

### 1. Secure Authentication
- Password hashing with bcrypt and unique salts
- Session-based login management
- Protection against credential stuffing

### 2. Authorization Controls
```python
# Example ACL implementation
ACLs = {
    'librarian': {'manage_catalog', 'approve_roles', 'borrow_books', 'return_books', 'view_catalog', 'reserve_books', 'library_resources', 'delete_user'},
    'faculty': {'borrow_books', 'return_books', 'view_catalog', 'reserve_books', 'library_resources'},
    'student': {'borrow_books', 'return_books', 'view_catalog', 'library_resources'}
}
```

### 3. User Provisioning
- Automatic approval for student accounts
- Admin approval required for faculty/librarian roles
- Audit trail of approvals

### 4. Database Security
- Parameterized queries prevent SQL injection
- Foreign key constraints maintain data integrity
- Proper indexing on sensitive fields

## 🔍 Security Considerations

- **Password Policy**: Minimum length requirements enforced
- **Session Security**: Flask-Login handles session management
- **Input Validation**: WTForms validates all user inputs
- **Role Verification**: All privileged actions verify user permissions
- **Database Protection**: ORM prevents direct SQL manipulation

## 📊 Testing Scenarios

1. **User Registration**: Test role assignment and approval workflow
2. **Authentication**: Verify password hashing and login validation
3. **Authorization**: Confirm role-based access restrictions
4. **Admin Functions**: Test user approval and deletion capabilities
5. **Security**: Attempt unauthorized access and privilege escalation

## 🎓 Learning Outcomes

This project demonstrates practical implementation of:
- Authentication vs. Authorization concepts
- Secure password storage and verification
- Role-based permission systems
- Database security best practices
- Web application security fundamentals

## 📈 Future Enhancements

- Multi-factor authentication (MFA)
- Password complexity requirements
- Session timeout management
- Audit logging for security events
- RESTful API with JWT tokens

## 🤝 Contributing

This project was developed as part of academic coursework in information security. Feedback and suggestions for security improvements are welcome!

---

**Note**: This is an educational project demonstrating security concepts. For production use, additional security measures would be recommended.
