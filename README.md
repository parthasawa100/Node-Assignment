
## Overview

Welcome to the world of Node.js development! This assignment outlines the key features and requirements for your Node.js project. The goal is to create a robust application with user authentication, role-based access control, and secure API endpoints.

## Assignment Requirements

### User Management

1. **Signup:**
   - Collect basic details (email, phone number, name, profile image, password) during the signup process.
   - Ensure at least one of the phone number or email is provided during signup.
   - Implement encryption for passwords.

2. **Login:**
   - Allow users to log in using email/phone and password.

3. **Modify User Details:**
   - Users can only modify their own name and profile image.
   - Phone number and email, once entered, cannot be changed.

4. **Delete User:**
   - Users should have the ability to delete their accounts.

### Roles and Access Control

5. **Roles:**
   - Define two roles: Admin and User.

6. **Admin Access:**
   - Admins can view, modify, and delete all user details.

7. **User Access:**
   - Users can only view, modify, and delete their own details.

### Admin Management

8. **Create Admin:**
   - Create APIs to allow the creation of admin accounts.

### Authentication and Security

9. **Authentication:**
   - Implement an authentication system using JSON Web Tokens (JWT).

10. **Password Encryption:**
   - Use bcrypt to securely encrypt user passwords.

### Image Storage

11. **Profile Image:**
   - Save profile images integrate with a third-party service Cloudinary.

### Database and Framework

12. **Framework:**
   - Utilize Express.js for API development.

13. **Database:**
   - Choosed MongoDB for the database.

### Data Validation

14. **Data Validation:**
    - Implement thorough data validation to ensure the correctness and integrity of input data.



# Environment Variables

To run the project, you need to set up the following environment variables. Create a `.env` file in the root of your project and add the following variables with your own values:

```plaintext
# .env

MONGO_URI="mongodb+srv://your-username:your-password@cluster0.your-mongodb.net/?retryWrites=true&w=majority"
JWT_SECRET="your-jwt-secret-key"
CLOUD_NAME="your-cloudinary-cloud-name"
CLOUD_KEY="your-cloudinary-api-key"
CLOUD_KEY_SECRET="your-cloudinary-api-key-secret"

