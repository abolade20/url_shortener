from flask import Blueprint, render_template, flash, redirect, url_for, request, send_file
from app import db
from app.models import User, URL, ClickLog
from app.forms import RegistrationForm, LoginForm, NewURLForm, SearchForm
from flask_login import login_user, current_user, logout_user, login_required
import qrcode
import os

main = Blueprint('main', __name__)

# ===== HOME =====

@main.route('/')
def home():
        if current_user.is_authenticated:
            return redirect(url_for('main.dashboard'))
        return render_template('home.html')


# ===== REGISTRATION =====

@main.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration (PRD 2.1: User Authentication)"""
    if current_user.is_authenticated:
        return render_template('dashboard.html')

    form = RegistrationForm()

    if form.validate_on_submit():
        # Check if email already exists
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered", 'danger')
            return redirect(url_for('main.signup'))
        
        # Check if username already exists
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already taken", 'danger')
            return redirect(url_for('main.signup'))
        
        # Create new user with bcrypt
        new_user = User(email=form.email.data, username=form.username.data)
        new_user.set_password(form.password.data)  # Uses bcrypt
        db.session.add(new_user)
        db.session.commit()
        
        flash("Account created successfully! Please log in.", 'success')
        return redirect(url_for('main.login'))
    
    return render_template('signup.html', form=form)


# ===== LOGIN =====

@main.route('/login', methods=['GET', 'POST'])
def login():
    """User login (PRD 2.1: User Authentication)"""
    if current_user.is_authenticated:
        return render_template('dashboard.html')
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and user.check_password(form.password.data):  # Uses bcrypt
            login_user(user, remember=form.remember.data)
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login unsuccessful. Check email and password.')
    
    return render_template('login.html', form=form)



@main.route('/logout')
@login_required
def logout():
    """User logout (PRD 2.1: User Authentication)"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.home'))


# ===== DASHBOARD =====

@main.route('/dashboard')
@login_required
def dashboard():
    """User dashboard (PRD 2.2: Dashboard)"""
    # Get search query from form
    search_form = SearchForm()
    query = request.args.get('q', '').strip()
    
    # Base query for user's URLs
    urls_query = URL.query.filter_by(user_id=current_user.id)
    
    # Apply search filter if query provided
    if query:
        urls_query = urls_query.filter((URL.original_url.ilike(f'%{query}%')) |(URL.short_url.ilike(f'%{query}%')))
    
    # Order by most recent
    urls = urls_query.order_by(URL.date_created.desc()).all()
    
    total_clicks = sum(url.click_count for url in urls) if urls else 0
    most_clicked = max(urls, key=lambda u: u.click_count) if urls else None
    
    return render_template('dashboard.html', urls=urls, total_urls=len(urls), total_clicks=total_clicks,most_clicked=most_clicked,search_form=search_form,query=query)


# ===== URL SHORTENING =====
@main.route('/new-url', methods=['GET', 'POST'])
@login_required
def create_url():
    """Create shortened URL (PRD 2.3: URL Shortening)"""
    form = NewURLForm()
    
    if form.validate_on_submit():
        original_url = form.original_url.data
        custom_alias = form.custom_alias.data.strip() if form.custom_alias.data else ''
        
        # Add https:// if no scheme
        if not original_url.startswith(('http://', 'https://')):
            original_url = 'https://' + original_url
        
        # Check if URL already shortened by this user
        existing = URL.query.filter_by(
            original_url=original_url,
            user_id=current_user.id
        ).first()
        
        if existing:
            flash("You already shortened this URL", 'info')
            return redirect(url_for('main.url_detail', url_id=existing.id))
        
        # Step 1: Generate short code FIRST (before creating URL)
        if custom_alias:
            # Check if custom alias already exists
            if URL.query.filter_by(short_url=custom_alias).first():
                flash("Custom alias already taken", 'danger')
                return redirect(url_for('main.create_url'))
            short_code = custom_alias
        else:
            # For auto-generated code, use a temporary value, then update
            short_code = None  # Will generate after getting ID
        
        # Step 2: Create URL entry
        new_url = URL(original_url=original_url, user_id=current_user.id, short_url='temp')
        db.session.add(new_url)
        db.session.flush()  # Get the ID without committing
        
        # Step 3: Now generate the actual short code with real ID
        if not custom_alias:
            short_code = encode_base62(new_url.id)
        
        new_url.short_url = short_code
        
        # Step 4: Generate QR code
        qr_filename = generate_qr(short_code)
        new_url.qr_filename = qr_filename
        
        # Step 5: Commit everything together
        db.session.commit()
        
        flash("URL shortened successfully!", 'success')
        return redirect(url_for('main.url_detail', url_id=new_url.id))
    
    return render_template('create_url.html', form=form)

# ===== URL DETAIL & ANALYTICS =====

@main.route('/url/<int:url_id>')
@login_required
def url_detail(url_id):
    """URL details page (PRD 2.2, 2.4: Dashboard, QR Code)"""
    url = URL.query.get_or_404(url_id)
    
    # Check ownership
    if url.user_id != current_user.id:
        flash("Unauthorized", 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Get click analytics
    clicks = ClickLog.query.filter_by(url_id=url_id).order_by(ClickLog.timestamp.desc()).all()
    
    return render_template('url_detail.html', url=url, clicks=clicks)


# ===== REDIRECT & CLICK TRACKING =====

@main.route('/r/<short_code>')
def redirect_short(short_code):
    """Redirect to original URL (PRD 2.3 Flow 4: Redirection)"""
    url = URL.query.filter_by(short_url=short_code).first_or_404()
    
    # Log click (PRD 2.2: Display link performance)
    log = ClickLog(
        url_id=url.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', 'Unknown')
    )
    url.click_count += 1
    db.session.add(log)
    db.session.commit()
    
    return redirect(url.original_url, code=302)


# ===== URL MANAGEMENT =====

@main.route('/url/<int:url_id>/delete', methods=['POST'])
@login_required
def delete_url(url_id):
    """Delete a URL (PRD 2.2: Dashboard - Quick actions)"""
    url = URL.query.get_or_404(url_id)
    
    # Check ownership
    if url.user_id != current_user.id:
        flash("Unauthorized", 'danger')
        return redirect(url_for('main.dashboard'))
    
    db.session.delete(url)
    db.session.commit()
    
    flash("URL deleted successfully", 'success')
    return redirect(url_for('main.dashboard'))


@main.route('/url/<int:url_id>/download-qr')
@login_required
def download_qr(url_id):
    """Download QR code (PRD 2.4: QR Code - Allow download)"""
    from flask import current_app
    
    url = URL.query.get_or_404(url_id)
    
    # Check ownership
    if url.user_id != current_user.id:
        flash("Unauthorized", 'danger')
        return redirect(url_for('main.url_detail', url_id=url_id))
    
    if not url.qr_filename:
        flash("QR code filename missing from database", 'danger')
        return redirect(url_for('main.url_detail', url_id=url_id))
    
    qr_path = os.path.join(current_app.root_path, 'static', 'qrcodes', url.qr_filename)
    
    print(f"QR filename: {url.qr_filename}")  # Debug
    print(f"QR path: {qr_path}")  # Debug
    print(f"File exists: {os.path.exists(qr_path)}")  # Debug
    
    if os.path.exists(qr_path):
        return send_file(qr_path, as_attachment=True, download_name=f'qr_{url.short_url}.png')
    
    flash(f"QR code not found at {qr_path}", 'danger')
    return redirect(url_for('main.url_detail', url_id=url_id))

# ===== HELPER FUNCTIONS =====

def encode_base62(n):
    """Convert integer to base62 string (for short URLs)
    
    Example: 1 -> '1', 62 -> '10', 123 -> '23'
    """
    base62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if n == 0:
        return base62[0]
    
    result = ""
    while n > 0:
        result = base62[n % 62] + result
        n //= 62
    return result


def generate_qr(short_code):
    """Generate QR code PNG (PRD 2.4: QR Code Generation)"""
    try:
        short_url = url_for('main.redirect_short', short_code=short_code, _external=True)
        qr = qrcode.make(short_url)
        
        # Use current_app to get the root path
        from flask import current_app
        qr_dir = os.path.join(current_app.root_path, 'static', 'qrcodes')
        os.makedirs(qr_dir, exist_ok=True)
        
        qr_filename = f"{short_code}.png"
        qr_path = os.path.join(qr_dir, qr_filename)
        qr.save(qr_path)
        
        return qr_filename
    except Exception as e:
        print(f"Error generating QR code: {e}")
        return None