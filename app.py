"""Initialize Movie Rex."""

import os
import requests

from datetime import datetime, timedelta
from urllib.parse import quote, quote_plus, urlencode
from uuid import uuid4

from email_validator import validate_email, EmailNotValidError
from flask import (
    Flask, Markup,  # abort, jsonify, flash
    redirect, render_template, request, url_for)
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, RecaptchaField
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from sqlalchemy import exc, and_  # , or_, Enum
from sqlalchemy.dialects.postgresql import UUID  # , ENUM
from wtforms import (
    SubmitField, StringField, PasswordField,
    TextAreaField, BooleanField,
    SelectField)
from wtforms_components import DateField
from wtforms.validators import (
    Length, EqualTo, InputRequired, ValidationError)


app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('MOVIEREX_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('MOVIEREX_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['RECAPTCHA_PUBLIC_KEY'] = os.environ.get(
    'MOVIEREX_RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.environ.get(
    'MOVIEREX_RECAPTCHA_PRIVATE_KEY')

app.config['MAIL_SERVER'] = os.environ.get('MOVIEREX_MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MOVIEREX_MAIL_PORT'))
app.config['MAIL_USE_SSL'] = bool(os.environ.get('MOVIEREX_MAIL_USE_SSL'))
app.config['MAIL_USERNAME'] = os.environ.get('MOVIEREX_MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MOVIEREX_MAIL_PASSWORD')

app.config['DEBUG'] = True
app.config['MAIL_DEBUG'] = True
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['TESTING'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True


login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

omdb_apikey = os.environ.get('OMDB_APIKEY')


# Required functions
####################

# Custom validators


def email_is_valid(form, field):
    """Validate email address for sign-up form."""
    try:
        return validate_email(field.data)
    except EmailNotValidError as e:
        raise ValidationError(e)


def email_is_in_database(form, field):
    """Initialize method to test whether email is in db for sign-up."""
    user = User.query.filter_by(email=field.data.lower()).first()
    if user:
        raise ValidationError('A user with that email address '
                              'already exists.')


def email_exists(form, field):
    """Check to see if the user is in the system for login form."""
    user = User.query.filter_by(email=field.data.lower()).first()
    if not user:
        error = Markup("User does not exist. <a href='{}'>"
                       "<strong>Create account</strong></a>"
                       .format(url_for('signup')))
        raise ValidationError(error)


def email_verified(form, field):
    """Check to see that the user's email address is confirmed."""
    user = User.query.filter_by(email=field.data.lower()).first()
    if not user.email_verified:
        error = Markup("Email address not confirmed. Please "
                       "check your email.")
        raise ValidationError(error)


def username_is_unique(form, field):
    """Check to see if a username already exists."""
    user = User.query.filter_by(username=field.data.lower()).first()
    if user:
        raise ValidationError('A user with that username '
                              'already exists.')


def password_matches(form, field):
    """Check to see if the password matches."""
    password = field.data.encode()
    user = User.query.filter_by(email=form.email.data.lower()).first()
    if user:
        hashed = user.password
        if not bcrypt.check_password_hash(hashed, password):
            error = Markup("Wrong password. <a href='{}'>"
                           "<strong class='text-info'>I forgot</strong></a>"
                           .format(url_for('forgot')))
            raise ValidationError(error)
    else:
        raise ValidationError()


def omdb_query(query_term, by='title'):
    """Query OMDb and return the result."""
    omdb = 'https://www.omdbapi.com/?'
    if by == 'title':
        omdb_request = omdb + urlencode(
            {'t': query_term, 'r': 'json', 'apikey': omdb_apikey})
    elif by == 'imdb_id':
        omdb_request = omdb + urlencode(
            {'i': query_term, 'r': 'json', 'apikey': omdb_apikey})

    result = requests.get(omdb_request)
    omdb_response = result.json()
    return omdb_response


def movie_exists(form, field):
    """Check OMDb to see if the movie exists."""
    title = field.data
    omdb_response = omdb_query(title)
    if omdb_response['Response'] != 'True':
        error = omdb_response['Error']
        raise ValidationError(error)


# Set IDs with uuid

def new_uuid():
    """Pass back a new uuid hex."""
    return str(uuid4())


def thirty_days_from_now():
    """Send back today's date plus thirty days."""
    return datetime.utcnow() + timedelta(30)


# Form models
#############


class LoginForm(FlaskForm):
    """Instantiate the login form."""

    email = StringField('email', validators=[
        InputRequired(message='Email address required.'),
        email_exists,
        email_verified])
    password = PasswordField('password', validators=[
        InputRequired(message='Password required.'),
        password_matches])
    remember = BooleanField('remember')
    submit = SubmitField('submit')


class InviteForm(FlaskForm):
    """Instantiate the invitation form."""

    email = StringField('email', validators=[
        InputRequired(message='Email address required.'),
        Length(max=255, message='Needs to be less than 255 characters.'),
        email_is_valid])
    first_name = StringField('first_name', validators=[
        InputRequired(message='First name required.'),
        Length(max=128, message='Max length is 128 characters.')])
    # recaptcha = RecaptchaField()
    submit = SubmitField('submit')


class SignUpForm(FlaskForm):
    """Instantiate the signup form."""

    email = StringField('email', validators=[
        InputRequired(message='Email address required.'),
        Length(max=255, message='Needs to be less than 255 characters.'),
        email_is_valid])
    first_name = StringField('first_name', validators=[
        InputRequired(message='First name required.'),
        Length(max=128, message='Max length is 128 characters.')])
    last_name = StringField('last_name', validators=[
        InputRequired(message='Last name required.'),
        Length(max=128, message='Max length is 128 characters.')])
    birthday = DateField('birthday', validators=[
        InputRequired(message='Birthday required.')])
    password = PasswordField('password', validators=[
        InputRequired(message='Password required.'),
        Length(min=8, max=160, message='Password must be between '
                                       '8 and 160 chars.'),
        EqualTo('confirm', message='Passwords must match.')])
    confirm = PasswordField('confirm', validators=[
        InputRequired(message='Please repeat password.'),
        EqualTo('password', message='Passwords must match.')])
    recaptcha = RecaptchaField()
    submit = SubmitField('submit')


class ReviewForm(FlaskForm):
    """Instantiate the review form."""

    rating = SelectField(
        'rating',
        choices=[
            (0, "Choose a rating."),
            (1, "★"),
            (2, "★★"),
            (3, "★★★"),
            (4, "★★★★"),
            (5, "★★★★★")],
        default=0,
        coerce=int,
        validators=[InputRequired()])
    review = TextAreaField('review', validators=[InputRequired()])
    notify_recommender = BooleanField('notify_recommender')
    submit = SubmitField('submit')


class RecommenderForm(FlaskForm):
    """Instantiate the form to add a recommender."""

    name = StringField('name', validators=[
        InputRequired(message='Name is required.'),
        Length(max=32, message='Name has to be less than 32 characters.')])
    email = StringField('email', validators=[
        InputRequired(message='Email address required.'),
        Length(max=255, message='Needs to be less than 255 characters.'),
        email_is_valid])
    submit = SubmitField('submit')


# http://wtforms.simplecodes.com/docs/0.6.1/fields.html#wtforms.fields.SelectField
# def select_recommenders(user):
#     """Populate the above select field with the current user's list."""
#     choices = [
#         (r.id, r.name) for r in Recommender.query.filter_by(
#             owner_id=user.id).order_by('name').all()]
#     return choices


class RecommendationForm(FlaskForm):
    """Instantiate the recommendation form."""

    name = StringField('name', validators=[
        InputRequired(),
        movie_exists])
    recommender = SelectField(
        'recommender', validators=[])
    submit = SubmitField('submit')

    # https://stackoverflow.com/questions/31619747/dynamic-select-field-using-wtforms-not-updating
    def __init__(self, *args, **kwargs):
        """Initiate the recommendation form."""
        super(RecommendationForm, self).__init__(*args, **kwargs)
        self.recommender.choices = [
            (r.id, r.name) for r in Recommender.query.filter_by(
                owner_id=current_user.id).order_by('name').all()]


# Database models
#################


class Friendship(db.Model):
    """Instantiate the class to hold a friendship."""

    __tablename__ = 'friendships'
    id = db.Column(UUID, primary_key=True)
    friend_one_id = db.Column(UUID, db.ForeignKey('users.id'), nullable=False)
    friend_two_id = db.Column(UUID, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(
        db.Enum('pending',
                'active',
                'declined',
                'blocked',
                name='status_types'), nullable=False)
    friend_one = db.relationship('User', foreign_keys=[friend_one_id])
    friend_two = db.relationship('User', foreign_keys=[friend_two_id])

    __table_args__ = (db.UniqueConstraint(
        'friend_one_id', 'friend_two_id', name='_unique_friendship'),)

    def __repr__(self):
        """Define how friendships will be repr'd."""
        return '<Friendship {!r} <=> {!r} ({!s})>'.format(
            self.friend_one.email,
            self.friend_two.email,
            self.status)


class User(UserMixin, db.Model):
    """Instantiate the user object."""

    __tablename__ = 'users'
    id = db.Column(UUID, primary_key=True)
    first_name = db.Column(db.String(128), nullable=False)
    last_name = db.Column(db.String(128))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.LargeBinary(), nullable=False)
    birthday = db.Column(db.String(32), nullable=False)
    created = db.Column(db.String(32), nullable=False)
    modified = db.Column(db.String(32))
    deleted = db.Column(db.String(32))
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    # last_signon = db.Column(db.String(32))

    recommenders = db.relationship(
        'Recommender', backref='owner', lazy='dynamic')

    recommendations = db.relationship(
        'Recommendation', backref='owner', lazy='dynamic')

    reviews = db.relationship(
        'Review', backref='owner', lazy='dynamic')

    def __init__(self, **kwargs):
        """Initialize a new user."""
        self.id = new_uuid()
        self.first_name = kwargs['first_name']
        self.last_name = kwargs['last_name']
        self.email = kwargs['email']
        self.password = kwargs['password']
        self.birthday = kwargs['birthday']
        self.created = datetime.utcnow()

    friendships = db.relationship(
        'Friendship',
        primaryjoin='or_((users.c.id == friendships.c.friend_one_id), '
                    '(users.c.id == friendships.c.friend_two_id))',
        lazy='dynamic')

    def friends(self):
        """Return a list of the user's friends."""
        friends = []
        fs = [f for f in self.friendships.all() if f.status == 'active']
        for f in fs:
            if f.friend_one != self and f.friend_two == self:
                friends.append(f.friend_one)
            elif f.friend_two != self and f.friend_one == self:
                friends.append(f.friend_two)
            else:
                raise Exception('Friendship is not valid.')
        return friends

    friend_requests_sent = db.relationship(
        'User',
        secondary=Friendship.__table__,
        primaryjoin='(users.c.id == friendships.c.friend_one_id)',
        secondaryjoin='(users.c.id == friendships.c.friend_two_id)',
        lazy='dynamic')

    friend_requests_received = db.relationship(
        'User',
        secondary=Friendship.__table__,
        primaryjoin='(users.c.id == friendships.c.friend_two_id)',
        secondaryjoin='(users.c.id == friendships.c.friend_one_id)',
        lazy='dynamic')

    def __repr__(self):
        """Define how the User class will be repr'd."""
        return '<User \'{0} {1}\', {2!r}>'.format(
            str(self.first_name), str(self.last_name), self.email)

#     def signon(self):
#         """Take note of when a user signs in."""
#         self.last_signon = datetime.utcnow()


class Movie(db.Model):
    """Instantiate the object representing the movie."""

    __tablename__ = 'movies'
    id = db.Column(UUID, primary_key=True)
    imdb_id = db.Column(db.String(12), unique=True)
    title = db.Column(db.Text)
    poster_href = db.Column(db.Text)


class Review(db.Model):
    """Instantiate the object representing a review."""

    __tablename__ = 'reviews'
    id = db.Column(UUID, primary_key=True)
    movie_id = db.Column(UUID, db.ForeignKey('movies.id'))
    owner_id = db.Column(UUID, db.ForeignKey('users.id'))

    movie = db.relationship('Movie', backref='review', lazy='dynamic')


class Recommender(db.Model):
    """Instantiate an object representing the recommender."""

    __tablename__ = 'recommenders'
    id = db.Column(UUID, primary_key=True)
    name = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(
        UUID, db.ForeignKey('users.id'), nullable=False)
    created = db.Column(db.DateTime, nullable=False)
    deleted = db.Column(db.DateTime)

    recommendations = db.relationship(
        'Recommendation', backref='recommender', lazy='dynamic')

    def __init__(self, **kwargs):
        """Initialize a recommender object."""
        self.id = new_uuid()
        self.name = kwargs['name']
        self.owner_id = kwargs['owner_id']
        self.email = kwargs['email']
        self.created = datetime.utcnow()


class Recommendation(db.Model):
    """Instantiate an object representing a recommendation."""

    __tablename__ = 'recommendations'
    id = db.Column(UUID, primary_key=True)
    recommender_id = db.Column(
        UUID, db.ForeignKey('recommenders.id'))
    owner_id = db.Column(
        UUID, db.ForeignKey('users.id'))
    name = db.Column(db.String(256), nullable=False)
    rating = db.Column(db.Integer)
    review = db.Column(db.Text)
    # watched = db.Column(db.Boolean, default=False, nullable=False)
    netflix_search = db.Column(db.Text)
    imdb_search = db.Column(db.Text)
    rotten_search = db.Column(db.Text)
    hulu_search = db.Column(db.Text)
    created = db.Column(db.DateTime, nullable=False)
    watched = db.Column(db.DateTime)
    deleted = db.Column(db.DateTime)

    def __init__(self, **kwargs):
        """Initialize a recommender object."""
        netflix_url = 'https://www.netflix.com/search?'
        imdb_url = 'http://www.imdb.com/find?'
        rotten_url = 'https://www.rottentomatoes.com/search/?'
        hulu_url = 'https://www.hulu.com/search?'

        self.id = new_uuid()
        self.recommender_id = kwargs['recommender_id']
        self.owner_id = kwargs['owner_id']
        self.name = kwargs['name']
        self.netflix_search = (
            netflix_url + urlencode({'q': self.name}, quote_via=quote))
        self.imdb_search = (
            imdb_url + urlencode({'q': self.name}, quote_via=quote_plus))
        self.rotten_search = (
            rotten_url + urlencode({'search': self.name}, quote_via=quote))
        self.hulu_search = (
            hulu_url + urlencode({'q': self.name}, quote_via=quote_plus))
        self.created = datetime.utcnow()

# View Routes
#############


@login_manager.user_loader
def load_user(user_id):
    """Load the user from given user_id."""
    # has to have str(), otherwise the function thinks it's an int.
    return User.query.get(str(user_id))


@app.route('/')
@login_required
def index():
    """Render the index view."""
    # watched = Recommendation.query.filter_by(watched=True).all()
    # not_watched = Recommendation.query.filter_by(watched=False).all()
    rec_form = RecommendationForm()
    not_watched = Recommendation.query.filter(and_(
        Recommendation.owner_id == current_user.id,
        Recommendation.watched == None, Recommendation.deleted == None))
    watched = Recommendation.query.filter(and_(
        Recommendation.owner_id == current_user.id,
        Recommendation.watched != None,
        Recommendation.deleted == None,
        Recommendation.rating == None,
        Recommendation.review == None))
    reviewed = Recommendation.query.filter(and_(
        Recommendation.owner_id == current_user.id,
        Recommendation.deleted == None,
        Recommendation.rating != None,
        Recommendation.review != None))

    return render_template(
        'dashboard.html',
        not_watched=not_watched,
        watched=watched,
        reviewed=reviewed,
        today=datetime.utcnow(),
        rec_form=rec_form)


@app.errorhandler(401)
def unauthorized(error):
    """Take the user to the login page if not logged in."""
    return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(error):
    """View for error 404."""
    return render_template('error.html', error=error)


@app.errorhandler(500)
def internal_error(error):
    """View for internal server error."""
    return render_template('error.html', error=error)


@app.route('/account')
@login_required
def account():
    """Render the account view."""
    return render_template('about.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Render the login view."""
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).one()
        login_user(user)
        # flash('Welcome, {}!'.format(current_user.first_name))
        return redirect(url_for('index'))

    return render_template('login.html', form=form)


@app.route('/confirm_email/<token>', methods=['GET'])
def confirm_email(token):
    """Confirm the user's email address."""
    # token is good for a week (60 * 60 * 24 * 7 = 604800)
    try:
        email = serializer.loads(token, salt='confirm_email', max_age=604800)
    except SignatureExpired as error:
        return render_template('error.html', error=error)

    try:
        user = User.query.filter_by(email=email).one()
    except exc.SQLAlchemyError as error:
        return render_template('error.html', error=error)

    user.email_verified = True

    try:
        db.session.add(user)
        db.session.commit()
    except exc.SQLAlchemyError as error:
        db.session.rollback()
        return render_template('error.html', error=error)

    return render_template('email_verified.html')


@app.route('/invite', methods=['GET', 'POST'])
@login_required
def invite():
    """Invite another user."""
    form = InviteForm()
    if request.method == 'POST' and form.validate_on_submit():
        return 'Nothing\'s here'

    return render_template('invite.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """Render the logout view."""
    logout_user()
    # flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Render the signup view."""
    form = SignUpForm()

    if request.method == 'POST' and form.validate_on_submit():
        first_name = form.first_name.data
        last_name = form.last_name.data
        email = form.email.data.lower()
        birthday = form.birthday.data
        password = form.password.data.encode()
        hashed = bcrypt.generate_password_hash(password)
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed,
            birthday=birthday)
        db.session.add(new_user)
        try:
            db.session.commit()
        except exc.SQLAlchemyError as error:
            db.session.rollback()
            return render_template('error.html', error=error)
        # flash('When this is done, an email alert will be sent to confirm.')

        token = serializer.dumps(email, salt='confirm_email')

        msg = Message(
            '[Movie Rex] Please confirm your email address',
            sender='karl.johnson@wholehog.nyc',
            recipients=[email])

        link = url_for('confirm_email', token=token, _external=True)

        msg.body = ("Hi {} {},\n\nPlease click the link below to confirm "
                    "your account.\n\n{}\n\nThanks,\n\n\nKarl"
                    .format(first_name, last_name, link))

        try:
            mail.send(msg)
        except:
            return render_template(
                'error.html',
                error='There was a problem sending your confirmation email.')

        return render_template('check_email.html')

    for email, errors in form.errors.items():
        for error in errors:
            print(error)
    return render_template('signup.html', form=form)


@app.route('/forgot')
def forgot():
    """Render the forgot view."""
    pass


@app.route('/about')
def about():
    """Render the about view."""
    return render_template('about.html')


@app.route('/add_recommender', methods=['GET', 'POST'])
@login_required
def add_recommender():
    """Add a new recommender."""
    form = RecommenderForm()

    if request.method == 'POST' and form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        new_recommender = Recommender(
            owner_id=current_user.id,
            name=name,
            email=email)
        db.session.add(new_recommender)
        try:
            db.session.commit()
            return redirect(url_for('index'))
        except:
            db.session.rollback()
            # flash('Database error.')
            return redirect(url_for('index'))

    return render_template('add_recommender.html', form=form)


@app.route('/delete_recommender/<recommender_id>', methods=['POST'])
@login_required
def delete_recommender(recommender_id):
    """Delete a recommender by id."""
    recommender = Recommender.query.filter_by(id=recommender_id).one()
    if recommender.owner_id == current_user.id:
        recommender.deleted = datetime.utcnow()
        db.session.commit()
        # flash('Recommender deleted.')
        return redirect(url_for('index'))
    else:
        # flash('You don\'t have access to that recommender.')
        return redirect(url_for('index'))


@app.route('/add_recommendation', methods=['GET', 'POST'])
@login_required
def add_recommendation():
    """Add a new recommendation."""
    form = RecommendationForm()

    if request.method == 'POST' and form.validate_on_submit():
        name = form.name.data
        recommender_id = form.recommender.data
        new_recommendation = Recommendation(
            owner_id=current_user.id,
            recommender_id=recommender_id,
            name=name)
        db.session.add(new_recommendation)
        db.session.commit()
        # flash('Recommendation added.')
        return redirect(url_for('index'))

    # form.recommender.choices = select_recommenders(current_user)
    return render_template('add_recommendation.html', form=form)


@app.route('/add_movie', methods=['GET', 'POST'])
@login_required
def add_movie():
    """Add a new movie."""
    form = None

    if request.method == 'POST' and form.validate_on_submit():
        query_term = form.title.data
        omdb_response = omdb_query(query_term)
        title = omdb_response['Title']
        imdb_id = omdb_response['imdbID']
        poster_href = omdb_response['Poster']

        if (db.session.query(
           db.exists().where(Movie.imdb_id == imdb_id)).scalar()):
            return render_template('movie.html', movie=omdb_response)
            # return redirect(url_for('index'))

        new_movie = Movie(
            id=new_uuid(),
            title=title,
            imdb_id=imdb_id,
            poster_href=poster_href)
        db.session.add(new_movie)
        try:
            db.session.commit()
            return render_template('movie.html', movie=omdb_response)
        except exc.SQLAlchemyError as error:
            db.session.rollback()
            return render_template('error.html', error=error)

    return render_template(None, form=form)


@app.route('/delete_recommendation/<recommendation_id>', methods=['POST'])
@login_required
def delete_recommendation(recommendation_id):
    """Delete a recommendation by id."""
    recommendation = Recommendation.query.filter_by(id=recommendation_id).one()
    if recommendation.owner_id == current_user.id:
        recommendation.deleted = datetime.utcnow()
        db.session.commit()
        # flash('Recommendation deleted.')
        return redirect(url_for('index'))
    else:
        # flash('You don\'t have access to that recommendation.')
        return redirect(url_for('index'))


@app.route('/watch/<recommendation_id>', methods=['POST'])
@login_required
def watch(recommendation_id):
    """Render the view for marking a recommendation as watched."""
    try:
        recommendation = Recommendation.query.filter_by(
            id=recommendation_id).one()
        recommendation.watched = datetime.utcnow()
        db.session.commit()
    except:
        db.session.rollback()
        return render_template('error.html', error='There was an error.')
    return redirect(url_for('index'))


@app.route('/unwatch/<recommendation_id>', methods=['POST'])
@login_required
def unwatch(recommendation_id):
    """Render the view for marking a recommendation as watched."""
    try:
        recommendation = Recommendation.query.filter_by(
            id=recommendation_id).one()
        recommendation.watched = None
        db.session.commit()
    except:
        db.session.rollback()
        return render_template('error.html', error='There was an error.')
    return redirect(url_for('index'))


@app.route('/add_review/<recommendation_id>', methods=['GET', 'POST'])
@login_required
def add_review(recommendation_id):
    """Take a review from the user."""
    form = ReviewForm()
    recommendation = Recommendation.query.filter_by(id=recommendation_id).one()

    if request.method == 'POST' and form.validate_on_submit():
        try:
            rating = form.rating.data
            review = form.review.data
            recommendation.rating = rating
            recommendation.review = review
            db.session.commit()
            return redirect(url_for('index'))
        except:
            db.session.rollback()
            return render_template('error.html', error='There was an error.')

    return render_template(
        'add_review.html', form=form, recommendation=recommendation)


@app.route('/edit_review/<recommendation_id>', methods=['GET', 'POST'])
@login_required
def edit_review(recommendation_id):
    """Render the view for marking a recommendation as watched."""
    form = ReviewForm()

    recommendation = Recommendation.query.filter_by(
        id=recommendation_id).one()

    if request.method == 'POST' and form.validate_on_submit():
        recommendation.rating = form.rating.data
        recommendation.review = form.review.data
        try:
            db.session.commit()
            return redirect(url_for('index'))
        except:
            db.session.rollback()
            return render_template('error.html', error='There was an error.')

    return render_template(
        'edit_review.html',
        recommendation=recommendation,
        form=form)


@app.route('/unreview/<recommendation_id>', methods=['POST'])
@login_required
def unreview(recommendation_id):
    """Render the view for marking a recommendation as watched."""
    try:
        recommendation = Recommendation.query.filter_by(
            id=recommendation_id).one()
        recommendation.rating = None
        recommendation.review = None
        db.session.commit()
    except:
        db.session.rollback()
        return render_template('error.html', error='There was an error.')

    return redirect(url_for('index'))


@app.route('/read_review/<recommendation_id>', methods=['GET'])
@login_required
def read_review(recommendation_id):
    """View a previously written review."""
    recommendation = Recommendation.query.filter_by(id=recommendation_id).one()
    data = {
        "recommender_name": recommendation.recommender.name,
        "rating": recommendation.rating,
        "review": recommendation.review,
    }
    return render_template('read_review.html', data=data)


if __name__ == '__main__':
    app.run()
