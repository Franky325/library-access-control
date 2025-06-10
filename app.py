# app.py
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

#Using flask and bcrypt for hashing
app = Flask(__name__)
bcrypt = Bcrypt(app)

#Setting up sqlalchemy and the database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/realm/OneDrive/Desktop/CMPE 132 Project Test 3/database.db'
app.config['SECRET_KEY'] = 'secretkey'
db = SQLAlchemy(app)

#Flask login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#User class
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=True)
    approved = db.Column(db.Boolean, default=False)

    authorizer = db.Column(db.String(20), db.ForeignKey('user.username')) 
    approver = db.relationship('User', foreign_keys=[authorizer], backref=db.backref('approved_users', lazy='dynamic'), remote_side='User.username')

#Approval class
class Approval(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    librarian_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

#LoginForm class
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

#RegisterForm class
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    role = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Role"})
    submit = SubmitField("Register")

    #Makes sure usernames cant be the same
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username is taken. Create a new one.")

#My access control lists to designate what privileges different roles have
ACLs = {
    'librarian': {'manage_catalog', 'approve_roles', 'borrow_books', 'return_books', 'view_catalog', 'reserve_books', 'library_resources', 'delete_user'},
    'faculty': {'borrow_books', 'return_books', 'view_catalog', 'reserve_books', 'library_resources'},
    'student': {'borrow_books', 'return_books', 'view_catalog', 'library_resources'}
}

#Home route
@app.route('/')
def home():
    return render_template('home.html')

#Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        #Checks hashed password make sure it matches
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)

#Dashboard route
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    role_privileges = set()

    #Figures out what privileges the role logged in is approved for
    if current_user.approved:
        role_privileges = ACLs.get(current_user.role, set())
    else:
        pending_approval = Approval.query.filter_by(user_id=current_user.id).first()

        if pending_approval:
            role_privileges = ACLs.get('student', set())
        else:
            role_privileges = ACLs.get('librarian', set())

    all_users = User.query.all()

    return render_template('dashboard.html', user=current_user, role_privileges=role_privileges, all_users=all_users)

#Approve_roles route
@app.route('/approve_roles', methods=['GET', 'POST'])
@login_required
def approve_roles():
    if current_user.role == 'librarian':
        #Grabs list of users pending approval for librarian
        pending_approvals = Approval.query.filter_by(librarian_id=current_user.id).all()

        #If current librarian is not the admin, include pending approvals for the admin
        if current_user.username != 'admin':
            admin_librarian = User.query.filter_by(username='admin').first()
            admin_approvals = Approval.query.filter_by(librarian_id=admin_librarian.id).all()
            pending_approvals += admin_approvals

        #Get user details for each pending approval
        users_pending_approval = [User.query.get(approval.user_id) for approval in pending_approvals]

        return render_template('approve_roles.html', user=current_user, users_pending_approval=users_pending_approval)
    else:
        return redirect(url_for('dashboard'))

#Approve_user route
@app.route('/approve_user/<int:user_id>', methods=['GET', 'POST'])
def approve_user(user_id):
    if current_user.role == 'librarian':
        user_to_approve = User.query.get(user_id)

        if user_to_approve:
            #Marks the user as approved
            user_to_approve.approved = True
            db.session.commit()

            #Remove the user from pending approvals
            approval_to_remove = Approval.query.filter_by(librarian_id=current_user.id, user_id=user_id).first()
            
            if approval_to_remove:
                db.session.delete(approval_to_remove)
                db.session.commit()

            return redirect(url_for('approve_roles'))
    return redirect(url_for('dashboard'))

#delete_user route
@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    #Makes sure it is an approved librarian
    if current_user.role == 'librarian':
        user_to_delete = User.query.get(user_id)

        if user_to_delete:
            #Deletes selected user
            db.session.delete(user_to_delete)
            db.session.commit()
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('dashboard'))

#logout route
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    #Hashes password
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        is_student = form.role.data.lower() == 'student'
        new_user = User(username=form.username.data, password=hashed_password, role=form.role.data.lower(), approved=is_student)

        #Adds user to database
        with app.app_context():
            db.session.add(new_user)
            db.session.commit()

            if form.role.data.lower() in ['faculty', 'librarian']:
                librarian = User.query.filter_by(role='librarian').first()
                approval = Approval(librarian_id=librarian.id, user_id=new_user.id)
                db.session.add(approval)
                db.session.commit()

            return redirect(url_for('login'))

    return render_template('register.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        #db.drop_all() #needed for testing purposes occasionally to reset database
        db.create_all()

        #Making a preapproved librarian
        librarian = User.query.filter_by(username='admin').first()
        if not librarian:
            librarian_password = bcrypt.generate_password_hash('admin').decode('utf-8')
            librarian = User(username='admin', password=librarian_password, role='librarian', approved=True)
            db.session.add(librarian)
            db.session.commit()
    app.run(debug=True)