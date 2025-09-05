import os
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from dotenv import load_dotenv

# -------------------- Config --------------------
load_dotenv()  # loads .env if present

app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')

# Database (SQLite) — lives in instance/ecommerce.db
if not os.path.exists('instance'):
    os.makedirs('instance', exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Uploads (payment screenshots)
UPLOAD_DIR = os.path.join(app.root_path, 'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_DIR
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB

# Email (Flask-Mail)
if os.getenv('USE_SMTP', '0') == '1':
    app.config.update(
        MAIL_SERVER='smtp.gmail.com',
        MAIL_PORT=587,
        MAIL_USE_TLS=True,
        MAIL_USERNAME=os.getenv('MAIL_USERNAME'),
        MAIL_PASSWORD=os.getenv('MAIL_PASSWORD'),
        MAIL_DEFAULT_SENDER=os.getenv('MAIL_USERNAME'),
    )
else:
    app.config.update(
        MAIL_SERVER='localhost',
        MAIL_PORT=8025,
        MAIL_DEFAULT_SENDER='noreply@example.com'
    )
mail = Mail(app)

db = SQLAlchemy(app)

# Admin email to receive screenshots
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@example.com')

# -------------------- Models --------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, p):
        self.password_hash = generate_password_hash(p)

    def check_password(self, p):
        return check_password_hash(self.password_hash, p)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False, default=0.0)
    image_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'))
    quantity = db.Column(db.Integer, default=1)

# -------------------- Helpers --------------------
def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    return User.query.get(uid)

def login_required(view_func):
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please login first.", "warn")
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper

def admin_required(view_func):
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or not user.is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for('items'))
        return view_func(*args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper

# -------------------- Routes --------------------
@app.route('/')
def home():
    # Root now shows index.html
    return render_template('index.html', user=current_user())

# ----- Auth -----
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        pwd = request.form.get('password', '').strip()
        if not uname or not pwd:
            flash("Username and password are required.", "error")
            return redirect(url_for('signup'))
        if User.query.filter_by(username=uname).first():
            flash("Username already exists.", "error")
            return redirect(url_for('signup'))
        u = User(username=uname, is_admin=(uname.lower() == 'admin'))
        u.set_password(pwd)
        db.session.add(u)
        db.session.commit()
        flash("Signup successful. Please login.", "ok")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        pwd = request.form.get('password', '').strip()
        u = User.query.filter_by(username=uname).first()
        if u and u.check_password(pwd):
            session['user_id'] = u.id
            flash("Logged in!", "ok")
            return redirect(url_for('items'))
        flash("Invalid credentials.", "error")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out.", "ok")
    return redirect(url_for('login'))

# ----- Items (shop) -----
@app.route('/items')
def items():
    items = Item.query.order_by(Item.created_at.desc()).all()
    return render_template('items.html', items=items, user=current_user())

# ----- Admin page: add/delete items -----
@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        price = float(request.form.get('price', '0') or 0)
        image_url = request.form.get('image_url', '').strip()
        if not name:
            flash("Item name is required.", "error")
        else:
            i = Item(name=name, price=price, image_url=image_url)
            db.session.add(i)
            db.session.commit()
            flash("Item added.", "ok")
        return redirect(url_for('admin'))
    items = Item.query.order_by(Item.created_at.desc()).all()
    return render_template('admin.html', items=items, user=current_user())

@app.route('/admin/delete/<int:item_id>', methods=['POST'])
@admin_required
def admin_delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    Cart.query.filter_by(item_id=item_id).delete()
    db.session.commit()
    flash("Item deleted.", "ok")
    return redirect(url_for('admin'))

# ----- Cart -----
@app.route('/cart')
@login_required
def cart():
    user = current_user()
    entries = Cart.query.filter_by(user_id=user.id).all()
    cart_items = []
    total = 0.0
    for e in entries:
        item = Item.query.get(e.item_id)
        if not item:
            continue
        line_total = item.price * max(1, e.quantity)
        total += line_total
        cart_items.append({
            'cart_id': e.id,
            'item_id': item.id,
            'name': item.name,
            'price': item.price,
            'quantity': e.quantity,
            'image_url': item.image_url,
            'line_total': line_total
        })
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/add-to-cart/<int:item_id>', methods=['POST'])
@login_required
def add_to_cart(item_id):
    user = current_user()
    item = Item.query.get_or_404(item_id)
    row = Cart.query.filter_by(user_id=user.id, item_id=item.id).first()
    if row:
        row.quantity = row.quantity + 1
    else:
        row = Cart(user_id=user.id, item_id=item.id, quantity=1)
        db.session.add(row)
    db.session.commit()
    flash(f"Added {item.name} to cart.", "ok")
    return redirect(url_for('items'))

@app.route('/cart/update/<int:cart_id>', methods=['POST'])
@login_required
def update_cart(cart_id):
    q = int(request.form.get('quantity', '1') or 1)
    row = Cart.query.get_or_404(cart_id)
    if q <= 0:
        db.session.delete(row)
    else:
        row.quantity = q
    db.session.commit()
    flash("Cart updated.", "ok")
    return redirect(url_for('cart'))

# ----- Payment flow -----
@app.route('/payment', methods=['GET', 'POST'])
@login_required
def payment():
    if request.method == 'POST':
        flash("Payment marked as completed. Please upload the screenshot.", "ok")
        return redirect(url_for('send_screenshot'))
    return render_template('payment.html')

@app.route('/send-screenshot', methods=['GET', 'POST'])
@login_required
def send_screenshot():
    if request.method == 'POST':
        f = request.files.get('screenshot')
        if not f or f.filename == '':
            flash("Please select an image file.", "error")
            return redirect(url_for('send_screenshot'))

        filename = secure_filename(f.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        f.save(path)

        try:
            msg = Message(
                subject="Payment Screenshot",
                recipients=[ADMIN_EMAIL],
                body=f"User {current_user().username} uploaded a payment screenshot."
            )
            with app.open_resource(path) as fp:
                ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else 'png'
                mime = f"image/{'jpeg' if ext in ['jpg', 'jpeg'] else ext}"
                msg.attach(filename, mime, fp.read())

            mail.send(msg)
            flash("Screenshot sent to admin email!", "ok")
        except Exception as e:
            flash(f"Email send simulated (or failed): {e}", "warn")

        return redirect(url_for('success'))
    return render_template('send_screenshot.html')

@app.route('/success')
@login_required
def success():
    Cart.query.filter_by(user_id=current_user().id).delete()
    db.session.commit()
    return render_template('success.html')

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# -------------------- Bootstrapping --------------------
def seed_data():
    if User.query.count() == 0:
        admin = User(username='admin', is_admin=True)
        admin.set_password('admin123')
        db.session.add(admin)
        demo = User(username='user', is_admin=False)
        demo.set_password('user123')
        db.session.add(demo)

    if Item.query.count() == 0:
        demo_items = [
            ("Red Summer Dress", 1299.0, "https://images.unsplash.com/photo-1542060748-10c28b62716c"),
            ("Classic Black Gown", 2499.0, "https://images.unsplash.com/photo-1519741497674-611481863552"),
            ("Floral Casual Dress", 1599.0, "https://images.unsplash.com/photo-1512436991641-6745cdb1723f"),
        ]
        for name, price, url in demo_items:
            db.session.add(Item(name=name, price=price, image_url=url))
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_data()
    print("Admin login → username: admin / password: admin123")
    print("User login  → username: user  / password: user123")
    print("NOTE: Email is using console mode unless USE_SMTP=1 is set.")
    app.run(debug=True)
