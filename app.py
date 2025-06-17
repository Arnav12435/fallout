from flask import Flask,render_template,url_for,redirect,request,flash,session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,IntegerField,BooleanField
from flask_wtf.file import FileField,FileAllowed
from wtforms.validators import InputRequired,Length,ValidationError,Email,DataRequired,Regexp,Optional
from flask_bcrypt import Bcrypt
from flask_login import login_user, LoginManager, login_required, logout_user, current_user
import os,random
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from authlib.integrations.flask_client import OAuth
from flask_migrate import Migrate


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get( 'SECRET_KEY','dev')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'arnavmohanty89@gmail.com'         
app.config['MAIL_PASSWORD'] = 'ttdn rudf wsbz sckm'          
app.config['MAIL_DEFAULT_SENDER'] = 'arnavmohanty89@gmail.com'
mail = Mail(app)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])






app.config['SQLALCHEMY_DATABASE_URI']= os.environ.get("DATABASE_URL")

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)
migrate = Migrate(app, db)

bcrypt= Bcrypt(app)
oauth = OAuth(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'access_type': 'offline',
        'prompt': 'consent'
    }
)


class User(db.Model, UserMixin):
    id = db.Column(db.String(10), primary_key=True)
    username=db.Column( db.String(20), nullable=False, unique=True)
    first_name=db.Column(db.String(50),nullable=False)
    last_name=db.Column(db.String(50),nullable=False)
    password=db.Column(db.String(80), nullable=False)
    email=db.Column(db.String(50), nullable=False, unique=True)
    phone_number=db.Column(db.String(15), nullable=False, unique=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin=db.Column(db.Boolean,default=False)
    photo=db.Column(db.String(255))
    
class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20),Regexp(r'^\w+$', message="Username must contain only letters, numbers or underscores")], render_kw={"placeholder": "Username"})
    
    
    first_name= StringField(validators=[
                           InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Firstname"})
    
    
    last_name = StringField(validators=[
                           InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Lastname"})
    
    
    password = PasswordField(validators=[
                             InputRequired(),  Regexp(
                             r'^(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{6,}$',
                            message="Password must have 1 uppercase, 1 digit, and be 6+ characters"
                            )], render_kw={"placeholder": "Password"})
    
    email = StringField('Email',validators=[
                           InputRequired(), Length(min=4, max=50),Email(message="Invalid email")], render_kw={"placeholder": "Email"})

    phone_number = StringField(validators=[
                            InputRequired(),Regexp(r'^[0-9]{10}$', message="Phone must be 10 digits")], render_kw={"placeholder": "Phone Number"})
    
    photo=FileField("Profile Photo",validators=[FileAllowed(['jpg','png','jpeg'], "Images only!")])
    
    
    
    
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')
            
class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20),Regexp(r'^\w+$', message="Username must contain only letters, numbers or underscores")], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20),Regexp(
                             r'^(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{6,}$',
                            message="Password must have 1 uppercase, 1 digit, and be 6+ characters"
                            )], render_kw={"placeholder": "Password"})
    remember=BooleanField('Remember Me')
    

    submit = SubmitField('Login')  
    
    
class UpdateProfileForm(FlaskForm):
    password = PasswordField(validators=[Optional(),
                               Regexp(
                             r'^(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{6,}$',
                            message="Password must have 1 uppercase, 1 digit, and be 6+ characters"
                            )], render_kw={"placeholder": "New Password"})
    
    email = StringField(validators=[
                           InputRequired(), Length(min=4, max=50),Email(message="Invalid email")], render_kw={"placeholder": "Email"})

    phone_number = StringField(validators=[
                            InputRequired(),Regexp(r'^[0-9]{10}$', message="Phone must be 10 digits")], render_kw={"placeholder": "Phone Number"})

    submit = SubmitField('Update')              



class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    submit = SubmitField('Send Reset Link')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        InputRequired(),
        Regexp(
            r'^(?=.*[A-Z])(?=.*\d)[A-Za-z\d@$!%*?&]{6,}$',
            message="Password must have 1 uppercase, 1 digit, and be 6+ characters"
        )
    ])
    submit = SubmitField('Reset Password')

class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[InputRequired()])
    submit = SubmitField('Verify OTP')










@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login',methods=['GET', 'POST'])
def login():
     form=LoginForm()
     if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user,remember=form.remember.data)
                session['user_email'] = user.email 
                if user.is_admin:
                    return redirect(url_for('admin'))
                return redirect(url_for('dashboard'))
     return render_template('login.html',form=form)
 
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/users')
@login_required
def list_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return "Access Denied", 403
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/promote/<string:user_id>', methods=['POST'])
@login_required
def promote_user(user_id):
    if not current_user.is_admin:
        return "Access Denied", 403  
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    
    return redirect(url_for('admin'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        otp = str(random.randint(100000, 999999))
        session['otp'] = otp

        # Store form data temporarily in session
        session['temp_user'] = {
              'username': form.username.data,
               'first_name': form.first_name.data,
               'last_name': form.last_name.data,
               'password': bcrypt.generate_password_hash(form.password.data).decode('utf-8'),
                'email': form.email.data,
                'phone_number': form.phone_number.data
        }

        if form.photo.data:
            photo = form.photo.data
            filename = secure_filename(photo.filename)
            session['temp_user']['photo'] = filename
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            session['temp_user']['photo'] = None

        
        msg = Message('Your OTP Code', recipients=[form.email.data])
        msg.body = f'Your One-Time Password (OTP) is {otp}. It is valid for 5 minutes.'
        mail.send(msg)

        flash('An OTP has been sent to your email.')
        return redirect(url_for('verify_registration_otp'))

    return render_template('register.html', form=form)


@app.route('/demote/<string:user_id>',methods=['POST'])
@login_required
def demote_user(user_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    user= User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return "You cant demote yourself.",400
    if user.is_super_admin:
        return "Cannot demote a super admin.",403
    user.is_admin= False
    db.session.commit()
    return redirect(url_for('admin'))


@app.route('/delete_user/<string:user_id>',methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return "Access denied",403
    user=User.query.get_or_404(user_id)
    if user.id== current_user.id:
        return "You cant delete yourself.",400
    if user.is_super_admin:
        return "Cannot delete a super admin.",403
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin'))    

@app.route('/update_profile',methods=['GET', 'POST'])
@login_required
def update_profile():
    form = UpdateProfileForm()
    if request.method == 'GET':
        form.email.data = current_user.email
        form.phone_number.data = current_user.phone_number 

    if form.validate_on_submit():
        if form.password.data:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            current_user.password=hashed_password
            
        
        current_user.email=form.email.data
        current_user.phone_number=form.phone_number.data
        db.session.commit()
        return redirect(url_for('dashboard'))
    
   
      
        
    
    return render_template('update_profile.html',form=form)


@app.route('/forgot_password', methods=[ 'GET','POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset-salt')
            link = url_for('reset_password', token=token, _external=True)

            msg = Message('Password Reset Request',
                          sender='arnavmohanty89@gmail.com',
                          recipients=[user.email])
            msg.body = f'Click this link to reset your password: {link}'
            mail.send(msg)

        return redirect(url_for('login'))  
    return render_template('forgot_password.html', form=form)




@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  
    except Exception:
        return 'The reset link is invalid or has expired.', 400

    user = User.query.filter_by(email=email).first()
    form = ResetPasswordForm()

    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_pw
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)


@app.route('/send-otp')

def send_otp():
    otp = str(random.randint(100000, 999999))
    session['otp'] = otp

   
    user_email = current_user.email  
    session['user_email'] = user_email

    msg = Message('Your OTP Code', recipients=[user_email])
    msg.body = f'Your One-Time Password (OTP) is {otp}. It is valid for 5 minutes.'
    mail.send(msg)

    form = OTPForm()
    return render_template('otp.html', form=form)





@app.route('/resend-otp')

def resend_otp():
    otp = str(random.randint(100000, 999999))
    session['otp'] = otp

    user_email = current_user.email
    msg = Message('Your OTP Code', recipients=[user_email])
    msg.body = f'Your new OTP is {otp}. It is valid for 5 minutes.'
    mail.send(msg)

    flash('A new OTP has been sent to your email.')
    return redirect(url_for('send_otp'))



@app.route('/verify-registration-otp', methods=['GET', 'POST'])
def verify_registration_otp():
    form = OTPForm()
    temp_user = session.get('temp_user')

    if not temp_user:
        flash("Session expired or invalid access.")
        return redirect(url_for('register'))

    if form.validate_on_submit():
        entered_otp = form.otp.data
        if entered_otp == session.get('otp'):
            def generate_custom_id():
                last_user = User.query.order_by(User.id.desc()).first()
                if last_user and last_user.id.startswith("CEN"):
                    last_num = int(last_user.id[3:])
                    return f"CEN{last_num + 1:03d}"
                return "CEN001"

            try:
                new_user = User(
                    id=generate_custom_id(),
                    username=temp_user['username'],
                    first_name=temp_user['first_name'],
                    last_name=temp_user['last_name'],
                    password=temp_user['password'],
                    email=temp_user['email'],
                    phone_number=temp_user['phone_number'],
                    photo=temp_user['photo']
                )
                db.session.add(new_user)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                flash(f"Error creating user: {str(e)}")
                return redirect(url_for('register'))

            session.pop('otp', None)
            session.pop('temp_user', None)

            logout_user()  # Clear any existing login session

            flash('OTP verified! You can now log in.')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.')

    return render_template('otp.html', form=form)












@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True,_scheme='https')
    return google.authorize_redirect(redirect_uri)


@app.route('/login/callback')
def google_callback():
    token = google.authorize_access_token()
    resp = google.get('https://openidconnect.googleapis.com/v1/userinfo')
    user_info = resp.json()
    email = user_info['email']
    user = User.query.filter_by(email=email).first()
    
    if not user:
        flash("User with this Google account is not registered.")
        return redirect(url_for('login'))

    login_user(user)
    session['user_email'] = user.email
    return redirect(url_for('dashboard'))




    





if __name__ == '__main__':
    app.run()
