from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy.ext.declarative import declarative_base
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)
Base = declarative_base()
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
# app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{app.root_path}/blog.db"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)

##CONFIGURE TABLES
class User(db.Model,UserMixin, Base):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(100), unique=True, nullable = False)
    password = db.Column(db.String(100), nullable = False)
    name = db.Column(db.String(100), nullable=False)
    posts = relationship("BlogPost",back_populates="users")
    comments = relationship("Comment", back_populates="author")


@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        # return db.session.get(entity = User, ident = user_id)
        return User.query.get(int(user_id))


class BlogPost(db.Model,Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))
    users = relationship("User",back_populates="posts")
    comments = relationship("Comment", back_populates="parent_post")

class Comment(db.Model,Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key = True)
    comment = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer(), db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")
    author = relationship("User", back_populates="comments")


with app.app_context():    
    db.create_all()

def admin_only(function):
    @wraps(function)
    def admin_only_wrapper(*args,**kwargs):
        if current_user.id == 1:
            print("Inside decorator")
            return function(*args,**kwargs)
        else:
            abort(404,"Un-authorized")
    return admin_only_wrapper
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET','POST'])
def register():
    reg_form = RegisterForm()
    if request.method == 'POST':
        if reg_form.validate():
            email = request.form['email']
            name = request.form['name']
            password = generate_password_hash(request.form['password'],'pbkdf2:sha256', salt_length=8)
            if not db.session.query(User).filter_by(email = email).first():
                new_user = User(
                    name=name,
                    email=email,
                    password = password
                )
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successfull','success')
                # return redirect(url_for('login'))
                return render_template('register.html',form = reg_form)
            else:
                flash('Email already exist for user, please login','warning')
                return redirect(url_for('login'))
        else:
            flash('Registration Failed','errors')
    return render_template('register.html', form=reg_form)

@app.route('/login', methods = ['GET','POST'])
def login():
    login_form = LoginForm()
    app.logger.info("Inside login")
    if request.method == 'POST' and login_form.validate():
        app.logger.info("email : %s",request.form['email'])
        user = db.session.query(User).filter_by(email = request.form['email']).first()
        if user:
            if check_password_hash(user.password,request.form['password']):
                login_user(user)
                flash("Welcome","success")
                return redirect(url_for('get_all_posts'))
            else:
                flash("Incorrect Password","errors")
                render_template("login.html", form = login_form)
        else:
            flash("User does not exist, check the email id","errors")
            render_template("login.html", form = login_form)
    return render_template("login.html", form = login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods = ['GET','POST'])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if request.method == 'POST':
        if current_user.is_authenticated:
            new_comment = Comment(
                comment = request.form['comment'],
                author = current_user,
                parent_post = db.session.query(BlogPost).filter_by(id=post_id).first()
            )
            db.session.add(new_comment)
            db.session.commit()
    all_comments = db.session.query(Comment).filter_by(post_id=post_id)
    return render_template("post.html", post=requested_post, form=comment_form, comments = all_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@login_required
@app.route("/new-post", methods = ['GET','POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                user_id=current_user.id,
                author=db.session.query(User).filter_by(id=current_user.id).first().name,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@login_required
@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@login_required
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
