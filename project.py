from flask import Flask, render_template, request
from flask import redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem
from database_setup import User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

# Database connection.
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu App"


'''Login Page for the website.'''


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase +
                    string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


'''Method to connect to login authentication
and to obtain authorization token'''


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is'
                                            'already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
            user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;'
    output += 'border-radius: 150px;-webkit-border-radius:'
    output += '150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

'''Method to logout the user from the session'''


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user'
                                            'not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully Logged out!.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token'
                                            'for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

'''Helper functions for authorisation'''


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# JSON APIs

'''Fetches JSON for Menu Items object'''


@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItem=[item.serialize for item in items])

'''Fetches JSON for a single Menu Item Object'''


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON/')
def MenuItemJSON(restaurant_id, menu_id):
    item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(MenuItem=[item.serialize])

'''Fetches JSON for Restaurant object'''


@app.route('/restaurant/JSON')
def RestaurantJSON():
        restaurants = session.query(Restaurant).all()
        return jsonify(Restaurant=[
            restaurant.serialize for restaurant in restaurants])


'''Landing page of the website that
shows a list of restaurants'''


@app.route('/')
@app.route('/restaurants')
def Restaurants():
    restaurants = session.query(Restaurant).all()
    if 'username' not in login_session:
        return render_template('publicIndex.html', restaurantOne=restaurants)
    else:
        return render_template('index.html', restaurantOne=restaurants)

# CRUD on Restaurant object

'''Method to add new Restaurant'''


@app.route('/restaurants/new/', methods=['GET', 'POST'])
def newRestaurant():
    # Checks if the user is logged and is authorised to add new restaurant
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newRestaurant = Restaurant(name=request.form['restaurantName'],
                                   user_id=login_session['user_id'])
        session.add(newRestaurant)
        session.commit()
        flash("New restaurant added!")
        return redirect(url_for('Restaurants'))
    else:
        return render_template('newRestaurant.html')


'''Method to edit restaurant informatin'''


@app.route('/restaurants/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    # Checks if the user is logged and is authorised to add new restaurant
    if 'username' not in login_session:
            return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(
                                                     id=restaurant_id).one()
    if restaurant.user_id != login_session['user_id']:
        output = "<body><script>function myFunction() {alert("
        output += "'You are not authorized to edit this restaurant."
        output += "Please create your own restaurant in order to edit.'"
        output += ");}</script><body onload='myFunction()'>"
        return output
    if request.method == 'POST':
        if request.form['restaurantName']:
            restaurant.name = request.form['restaurantName']
        session.add(restaurant)
        session.commit()
        flash("Restaurant edited")
        return redirect(url_for('Restaurants'))
    else:
        return render_template('editRestaurant.html',
                               restaurantOne=restaurant)


'''Method to delete the restaurant'''


@app.route('/restaurants/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    # Checks if the user is logged and is authorised to add new restaurant
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(
                                                     id=restaurant_id).one()
    if restaurant.user_id != login_session['user_id']:
        output = "<body><script>function myFunction() {alert("
        output += "'You are not authorized to delete this restaurant."
        output += "Please create your own restaurant in order to delete.'"
        output += ");}</script><body onload='myFunction()'>"
        return output
    if request.method == 'POST':
        session.delete(restaurant)
        session.commit()
        flash("Restaurant deleted")
        return redirect(url_for('Restaurants'))
    else:
        return render_template('deleteRestaurant.html',
                               restaurantOne=restaurant)


'''Method to display Menu Items of a particular restaurant'''


@app.route('/restaurant/<int:restaurant_id>/menu/')
def restaurantMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    creator = getUserInfo(restaurant.user_id)
    items = session.query(MenuItem).filter_by(
            restaurant_id=restaurant_id).all()
    if 'username' not in login_session or creator.id != login_session[
                                                                      'user_id'
                                                                      ]:
            return render_template('publicMenu.html', restaurant=restaurant,
                                   items=items, creator=creator)
    else:
            return render_template('menu.html',
                                   restaurant=restaurant, items=items,
                                   creator=creator)


'''Method for description of particular menu item'''


@app.route('/restaurant/<int:restaurant_id>/<int:menu_id>/menu/description/',
           methods=['GET', 'POST'])
def menuDescription(restaurant_id, menu_id):
    menuItem = session.query(MenuItem).filter_by(id=menu_id).one()
    return render_template('menuDescription.html', restaurant_id=restaurant_id,
                           item=menuItem)

# CRUD on Menu Items Object

'''Method to add new Menu Item for a particular restaurant'''


@app.route('/restaurant/<int:restaurant_id>/menu/new/',
           methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    # Checks if the user is logged and is authorised to add new restaurant
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if login_session['user_id'] != restaurant.user_id:
        output = "<body><script>function myFunction() {alert("
        output += "'You are not authorized to add menu item "
        output += "to this restaurant."
        output += "Please create your own restaurant in order to "
        output += "add menu item.'"
        output += ");}</script><body onload='myFunction()'>"
        return output
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['menuName'],
                           description=request.form[
                           'description'], price=request.form['price'],
                           course=request.form['course'],
                           restaurant_id=restaurant_id)
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item '
              'Successfully Created' % (newItem.name))
        return redirect(url_for('restaurantMenu',
                                restaurant_id=restaurant_id))
    else:
        return render_template('newMenuItem.html',
                               restaurant_id=restaurant_id)

'''Method to edit menu item for a particular restaurant'''


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit/',
           methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    # Checks if the user is logged and is authorised to add new restaurant
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    editMenu = session.query(MenuItem).filter_by(id=menu_id).one()
    if login_session['user_id'] != restaurant.user_id:
        output = "<body><script>function myFunction() {alert("
        output += "'You are not authorized to edit menu item "
        output += "to this restaurant."
        output += "Please create your own restaurant in order to "
        output += "edit menu item.'"
        output += ");}</script><body onload='myFunction()'>"
        return output

    if request.method == 'POST':
        if request.form['menuName']:
            editMenu.name = request.form['menuName']
        if request.form['menuCourse']:
            editMenu.course = request.form['menuCourse']
        if request.form['menuDescription']:
            editMenu.description = request.form['menuDescription']
        if request.form['menuPrice']:
            editMenu.price = request.form['menuPrice']
        session.add(editMenu)
        session.commit()
        flash(" Menu Item has been edited!")
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('editMenuItem.html',
                               restaurant_id=restaurant_id,
                               menu_id=menu_id, item=editMenu)


'''Method to delete menu item for a particular restaurant'''


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete/',
           methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    # Checks if the user is logged and is authorised to add new restaurant
    if 'username' not in login_session:
        return redirect('/login')
    deleteMenu = session.query(MenuItem).filter_by(id=menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if login_session['user_id'] != restaurant.user_id:
        output = "<body><script>function myFunction() {alert("
        output += "'You are not authorized to delete menu item "
        output += "to this restaurant."
        output += "Please create your own restaurant in order to "
        output += "delete menu item.'"
        output += ");}</script><body onload='myFunction()'>"
        return output

    if request.method == 'POST':
        session.delete(deleteMenu)
        session.commit()
        flash("Menu Item has been deleted")
        return redirect(url_for('restaurantMenu', restaurant_id=restaurant_id))
    else:
        return render_template('deleteMenuItem.html',
                               restaurant_id=restaurant_id,
                               menu_id=menu_id, item=deleteMenu)

if __name__ == '__main__':
    app.secret_key = 'super_secret'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
