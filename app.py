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








UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER




oauth = OAuth(app)






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



    

    
    
    
    
    
    
    
   
               
    
    


   
     
    









@app.route('/')
def home():
    return render_template('home.html')



 
@app.route('/dashboard', methods=['GET', 'POST'])

def dashboard():
    user_info = session.get('user_info')
    if not user_info:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=user_info)



@app.route('/logout', methods=['GET', 'POST'])

def logout():
    session.clear()
    return redirect(url_for('home'))
   






    
    
               
        
      





    


       



















           











@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True,_scheme='https')
    return google.authorize_redirect(redirect_uri)


@app.route('/login/callback')
def google_callback():
    token = google.authorize_access_token()

    resp = google.get('https://openidconnect.googleapis.com/v1/userinfo')
    user_info = resp.json()

    google_id = user_info.get('sub')           
    email = user_info.get('email')
    full_name = user_info.get('name') or ""
    picture = user_info.get('picture')

    # Split full_name into first and last name (very basic split)
    name_parts = full_name.split()
    first_name = name_parts[0] if len(name_parts) > 0 else "Google"
    last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "User"

    # Generate a unique username (you may want a better system)
    username = email.split("@")[0]

    # Dummy password and phone (as they are required fields in your model)
    dummy_password = "google_oauth_dummy"
    dummy_phone = "0000000000"

    user = User.query.filter_by(email=email).first()

    if not user:
        user = User(
            id=google_id[:10],  # truncate to match id length
            username=username,
            first_name=first_name,
            last_name=last_name,
            password=dummy_password,
            email=email,
            phone_number=dummy_phone,
            photo=picture,
            is_admin=False,
            is_super_admin=False
        )
        db.session.add(user)
        db.session.commit()
        flash("New user registered via Google.", "success")
    else:
        flash("Welcome back!", "success")

    login_user(user)
    session['user_email'] = user.email
    session['name'] = f"{user.first_name} {user.last_name}"
    session['picture'] = user.photo

    return redirect(url_for('dashboard'))






    





if __name__ == '__main__':
    app.run()
