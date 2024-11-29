#Role-Based Access Control (RBAC) System
#Overview
This project demonstrates the implementation of Authentication, Authorization, and Role-Based Access Control (RBAC) in a web application. The system securely manages user accounts, assigns roles, and grants access to features based on the user's assigned role.

#Features
User Registration:

Allows new users to register with a unique username, password, and a selectable role (Admin, Moderator, User).
Passwords are securely hashed using werkzeug.security.
User Authentication:

Users can log in using their username and password.
The system validates the credentials and establishes a session upon successful login.
#Role-Based Authorization:

Users are assigned one of the following roles: Admin, Moderator, or User.
Role-specific routes restrict access to certain pages:
Admin: Access to Admin Dashboard.
Moderator: Access to Moderator Dashboard and lower-level functionalities.
User: Limited access to general features.
Session Management:

User sessions are maintained during the login session and cleared upon logout.
#Technologies Used
Flask: Python web framework for handling routes, templates, and sessions.
Flask-SQLAlchemy: ORM for managing the SQLite database.
SQLite: Lightweight database for storing user credentials and roles.
Bootstrap: Frontend framework for styling and responsive design.
#System Architecture
Models:
User: Stores user credentials (username, hashed password) and their assigned role.
Routes:
/register/: Handles user registration.
/login/: Authenticates users and establishes their session.
/logout/: Ends the user session.
/dashboard/: Displays a dashboard accessible to all authenticated users.
/admin/: Restricted to Admins.
/moderator/: Accessible by Admins and Moderators.
#Setup Instructions
Clone the repository:

bash
Copy code
git clone https://github.com/yourusername/rbac-system.git
cd rbac-system
Create a virtual environment and install dependencies:

bash
Copy code
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
Run the application:

bash
Copy code
flask run
Open the application in your browser at http://127.0.0.1:5000/.
