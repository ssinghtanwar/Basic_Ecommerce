from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['JWT_SECRET_KEY'] = 'secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seller = db.relationship('User', backref=db.backref('products', lazy=True))

    def __repr__(self):
        return f"Product('{self.name}', '{self.price}')"
    

class ProductResource:
    def get_products(self):
        products = Product.query.all()
        products_list = []
        for product in products:
            products_list.append({'id': product.id, 'name': product.name, 'price': product.price, 'seller_id': product.seller_id})
        return jsonify({'products': products_list})


class Security:
    @staticmethod
    def register():
        data = request.get_json()
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(username=data['username'], password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return jsonify ({'message': 'User created successfully'})
    @staticmethod
    def login():
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        if user and bcrypt.check_password_hash(user.password, data['password']):
            access_token = create_access_token(identity=user.id)
            return jsonify({'access_token': access_token})
        return jsonify({'error': 'Invalid credentials'}), 401
    
product_resource = ProductResource()
security = Security()
    
@app.route('/register', methods=['POST'])
def register():
    return security.register()

@app.route('/login', methods=['POST'])
def login():
    return security.login()

@app.route('/products', methods=['GET'])
def get_products():
    return product_resource.get_products()

if __name__ == '__main__':
    app.run(debug=True)