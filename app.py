from flask import Flask, redirect, render_template, request, url_for, session, escape
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, user_logged_in
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from sqlalchemy import ForeignKey

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'G20ttjQPbdxdUwU4n2n0j'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable = False, unique = True)
    password = db.Column(db.String(80), nullable = False)
    tasks = db.relationship('Task', backref='user')

    def __repr__(self):
        return '<User %r>' % self.id


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    description = db.Column(db.String(500))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    deadline = db.Column(db.DateTime)
    completed = db.Column(db.Boolean, default = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Task %r>' % self.id

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exist. Please choose a different one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


@app.route('/', methods=['POST', 'GET'])
@login_required
def index():
    current_user = User.query.filter_by(username = escape(session['username'])).first()
    if request.method == 'POST':
        task_name = request.form['name']        
        new_task = Task(name=task_name, user_id=current_user.id)
        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/')
        except:
            return 'There was an issue adding your task'

    else:
        done_tasks = Task.query.order_by(Task.date_created).filter_by(user_id = current_user.id).filter_by(completed=True).all()
        todo_tasks = Task.query.order_by(Task.date_created).filter_by(user_id = current_user.id).filter_by(completed=False).all()
        return render_template('index.html', done_tasks=done_tasks, todo_tasks=todo_tasks, username = current_user.username)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    task_to_del = Task.query.get_or_404(id)
    try:
        db.session.delete(task_to_del)
        db.session.commit()
        return redirect('/')
    except:
        return 'There was an issue deleting your task'


@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    task = Task.query.get_or_404(id)
    if request.method == 'POST':
        task.name = request.form['name']
        task.description = request.form['description']
        if(len(request.form['deadline']) > 1):
            task.deadline = datetime.fromisoformat(request.form['deadline'])
        else:
            task.deadline = None
        
        try:
            db.session.commit()
            return redirect('/')
        except:
            return 'There was an issue updating your task'
    else:
        return render_template('update.html', task = task)

@app.route('/mark/<int:id>')
@login_required
def mark(id):
    task = Task.query.get_or_404(id)
    try:
        task.completed = not (task.completed)
        db.session.commit()
        return redirect('/')
    except:
        return 'There was an issue marking your task'

@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("register.html", form=form)

@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                session['username'] = request.form['username']
                login_user(user)
                return redirect('/')
    return render_template("login.html", form=form)


@app.route('/logout', methods=["POST", "GET"])
@login_required
def logout():
    session.pop('username', None)
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)