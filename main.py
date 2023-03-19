# main.py

import mimetypes
mimetypes.add_type('application/javascript', '.js')
mimetypes.add_type('text/css', '.css')
from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response, send_from_directory, \
    send_file
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity, JWTManager
from dotenv import load_dotenv
import os
from flask_jwt_extended.exceptions import NoAuthorizationError
from sqlalchemy.orm import sessionmaker
from database import db
from flask_jwt_extended.view_decorators import verify_jwt_in_request
from functools import wraps, partial
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()
app = Flask(__name__, static_url_path='/static')
app.wsgi_app = ProxyFix(app.wsgi_app)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'shopping_list.db')
app.config['JWT_SECRET_KEY'] = os.environ['JWT_SECRET_KEY']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600
app.config['MIME_TYPES'] = {'js': 'application/javascript'}

jwt = JWTManager(app)
db.init_app(app)



from models import User, ShoppingList, Item, GroceryType, add_grocery_types



def jwt_required(fn=None, optional=False):
    if fn is None:
        return partial(jwt_required, optional=optional)
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            access_token = request.cookies.get("access_token")
            if access_token:
                request.environ["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"
            verify_jwt_in_request()
            return fn(*args, **kwargs)
        except NoAuthorizationError:
                return redirect(url_for('login'))

    return wrapper


@app.route('/register', methods=['POST', 'GET'])
def register():

    if request.method == 'GET':
        return render_template('register.html')


    if request.method == 'POST':
        username = request.form['username']
        encrypted_password = request.form['password']
        salt = request.form['salt']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'success': False, 'error': 'Username already exists'})

        user = User(username=username, password=encrypted_password, salt=salt)
        db.session.add(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User registered successfully'})

@app.route('/api/user/<username>', methods=['GET'])
def get_user_salt(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({'salt': user.salt})
    return jsonify({'error': 'User not found'}), 404

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    if request.method == 'POST':
        username = request.form['username']

        encrypted_password = request.form['password']

        user = User.query.filter_by(username=username).first()


        if user and encrypted_password == user.password:
            access_token = create_access_token(identity=user.id)
            response = make_response(jsonify({"message": "Login successful"}))
            response.set_cookie("access_token", access_token, httponly=True, secure=True)
            return response
        else:
            return jsonify({"error": "Invalid credentials"}), 401



@app.route('/logout', methods=['GET'])
@jwt_required(optional=True)
def logout():
    response = make_response(redirect(url_for('login')))
    response.set_cookie('access_token', '', expires=0, httponly=True, secure=True)
    return response

@app.route('/shopping_lists', methods=['GET', 'POST'])
@jwt_required(optional=True)
def shopping_lists():
    user_id = get_jwt_identity()
    if user_id is not None:
        user = User.query.get(user_id)
        if request.method == 'POST':
            name = request.form['name']
            shopping_list = ShoppingList(name=name, user=user)
            db.session.add(shopping_list)
            db.session.commit()
        encrypted_shopping_lists = user.shopping_lists
        return render_template('shopping_lists.html', shopping_lists=encrypted_shopping_lists, user=True)
    return redirect(url_for('login'))

@app.route('/')
@jwt_required(optional=True)
def index():
    user_id = get_jwt_identity()
    if user_id is None:
        return redirect(url_for('login'))

    return redirect(url_for('shopping_lists'))


@app.route('/shopping_list/<int:shopping_list_id>', methods=['GET', 'POST', 'DELETE'])
@jwt_required(optional=True)
def shopping_list(shopping_list_id):
    user_id = get_jwt_identity()
    if user_id is None:
        return redirect(url_for('login'))

    shopping_list = ShoppingList.query.filter_by(id=shopping_list_id, user_id=user_id).first()
    if not shopping_list:
        return jsonify({'error': 'Shopping list not found'})

    if request.method == 'GET':

        user_id = get_jwt_identity()
        if user_id is None:
            return redirect(url_for('login'))
        grocery_types = GroceryType.query.all()
        return render_template('shopping_list.html', shopping_list=shopping_list, grocery_types=grocery_types, user=True)

    if request.method == 'POST':

        user_id = get_jwt_identity()
        if user_id is None:
            return redirect(url_for('login'))
        encrypted_name = request.form['encrypted_name']
        encrypted_quantity = request.form['encrypted_quantity']
        item_type = request.form['item-type']
        checked = request.form['checked'] == 'true'
        grocery_type = GroceryType.query.filter_by(id=item_type).first()
        item = Item(name=encrypted_name, quantity=encrypted_quantity,
                    shopping_list_id=shopping_list_id, checked=checked, grocery_type_id=item_type, grocery_type=grocery_type)
        db.session.add(item)
        db.session.commit()
        return jsonify({'message': 'Item added'})

    if request.method == 'DELETE':
        # Delete all items associated with the shopping list
        for item in shopping_list.items:
            db.session.delete(item)

        # Delete the shopping list
        db.session.delete(shopping_list)
        db.session.commit()
        return jsonify({'message': 'Shopping list and all associated items deleted'})


@app.route('/grocery_types', methods=['GET'])
@jwt_required(optional=True)
def grocery_types():
    types = GroceryType.query.all()
    return jsonify([{'id': t.id, 'name': t.name} for t in types])

@app.route('/item', methods=['POST'])
@jwt_required(optional=True)
def add_item():
    encrypted_name = request.form['encrypted_name']
    shopping_list_id = request.form['shopping_list_id']
    encrypted_quantity = int(request.form.get('encrypted_quantity', 1))
    encrypted_price = request.form.get('encrypted_price', None)
    grocery_type_id = request.form.get('grocery_type_id', None)


    item = Item(name=encrypted_name, shopping_list_id=shopping_list_id, quantity=encrypted_quantity,
                price=encrypted_price, grocery_type_id=grocery_type_id)
    db.session.add(item)
    db.session.commit()
    return jsonify({'message': 'Item added'})

@app.route('/item/<int:item_id>', methods=['PUT', 'DELETE'])
@jwt_required(optional=True)
def item(item_id):

    user_id = get_jwt_identity()
    item = Item.query.get(item_id)
    if not item or item.shopping_list.user_id != user_id:
        return jsonify({'error': 'Item not found'})

    if request.method == 'PUT':
        encrypted_name = request.form.get('encrypted_name', item.name)
        encrypted_quantity = request.form.get('encrypted_quantity', item.quantity)
        item_type = request.form['item-type']
        grocery_type = GroceryType.query.filter_by(id=item_type).first()

        item.grocery_type = grocery_type
        item.name = encrypted_name
        item.quantity = encrypted_quantity

        db.session.commit()
        return jsonify({'message': 'Item updated'})

    if request.method == 'DELETE':
        db.session.delete(item)
        db.session.commit()
        return jsonify({'message': 'Item deleted'})

@app.route('/items/<int:item_id>/toggle_checked', methods=['POST'])
@jwt_required
def toggle_marked(item_id):
    user_id = get_jwt_identity()
    if user_id is None:
        return redirect(url_for('login'))

    item = Item.query.get(item_id)
    if item is None or item.shopping_list.user_id != user_id:
        return jsonify({"message": "Item not found or not authorized"}), 404

    item.checked = not item.checked
    db.session.commit()
    return jsonify({"message": "Item marked state updated"}), 200

@app.route('/login.html', methods=['GET'])
def login_page():
    return render_template('login.html')


@app.route('/register.html', methods=['GET'])
def register_page():
    return render_template('register.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        add_grocery_types()

        engine = db.get_engine()
        Session = sessionmaker(bind=engine)
    app.run(debug=False,host='0.0.0.0',port=5604)

