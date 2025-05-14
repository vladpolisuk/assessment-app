from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import json
from datetime import datetime
import sys
import os
import tempfile
import subprocess
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import logging
from logging.handlers import RotatingFileHandler
import traceback
import re
import time
import random
from collections import defaultdict

# Initialize Flask app
app = Flask(__name__)

# Configure app
app.config['SECRET_KEY'] = 'your-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure required directories exist
for directory in [app.config['UPLOAD_FOLDER'], 'blocks']:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure logging
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def debug_print(message):
    """Функция для отладочной печати"""
    print(f"[DEBUG] {message}")
    logger.debug(message)
    # Also write to a file for persistence
    with open('debug.log', 'a', encoding='utf-8') as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

try:
    debug_print("Импорт модулей выполнен успешно")

    @app.template_filter('from_json')
    def from_json_filter(value):
        """Фильтр для преобразования JSON строки в Python объект"""
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value

    debug_print("Flask и SQLAlchemy инициализированы")

except Exception as e:
    print(f"Критическая ошибка при инициализации приложения: {str(e)}", file=sys.stderr)
    exit(1)

# Модели
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default='user')

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    @property
    def role_display(self):
        debug_print(f"Определение роли для пользователя {self.username}. Текущая роль: {self.role}")
        roles = {
            'user': 'Пользователь',
            'expert': 'Эксперт',
            'admin': 'Администратор',
            'working_group': 'Рабочая группа'
        }
        display_role = roles.get(self.role, 'Пользователь')
        debug_print(f"Отображаемая роль: {display_role}")
        return display_role

class AssessmentBlock(db.Model):
    __tablename__ = 'assessment_block'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    weight = db.Column(db.Float, default=1.0)  # Добавляем поле weight
    max_score = db.Column(db.Float, default=10.0)  # Добавляем поле max_score
    questions = db.relationship('AssessmentQuestion', back_populates='block', lazy=True)

class AssessmentQuestion(db.Model):
    __tablename__ = 'assessment_question'
    id = db.Column(db.Integer, primary_key=True)
    block_id = db.Column(db.Integer, db.ForeignKey('assessment_block.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'multiple_choice', 'open_ended', 'code', 'matching', 'expert_evaluation'
    options = db.Column(db.Text)  # JSON для вариантов ответов
    correct_answer = db.Column(db.Text)  # JSON для правильного ответа
    points = db.Column(db.Integer, default=1)
    code_template = db.Column(db.Text)  # Шаблон кода для вопросов типа 'code'
    test_cases = db.Column(db.Text)  # JSON для тестовых случаев
    example_solutions = db.Column(db.Text)  # JSON для примеров успешных решений
    block = db.relationship('AssessmentBlock', foreign_keys=[block_id])
    option_scores = db.Column(db.Text)  # JSON для баллов по вариантам
    description = db.Column(db.Text)  # Описание для вопросов типа 'expert_evaluation'
    criteria = db.Column(db.Text)  # JSON для критериев оценки
    max_score = db.Column(db.Float)  # Максимальный балл для экспертной оценки
    weight = db.Column(db.Float)  # Вес вопроса в блоке

    def get_definitions(self):
        """Получить список определений для matching-вопроса"""
        if self.type == 'matching':
            try:
                data = json.loads(self.options)
                if isinstance(data, dict):
                    return data.get('definitions', [])
                elif isinstance(data, list):
                    return data
                return []
            except (json.JSONDecodeError, TypeError):
                return []
        return []

    def get_criteria(self):
        """Получить список критериев для экспертной оценки"""
        if self.type == 'expert_evaluation':
            try:
                return json.loads(self.criteria)
            except (json.JSONDecodeError, TypeError):
                return []
        return []

    def get_terms(self):
        """Получить список терминов для matching-вопроса"""
        if self.type == 'matching':
            try:
                data = json.loads(self.options)
                if isinstance(data, dict):
                    return data.get('options', [])
                elif isinstance(data, list):
                    return data
                return []
            except (json.JSONDecodeError, TypeError):
                return []
        return []

    def get_correct_matches(self):
        """Получить правильные соответствия для matching-вопроса"""
        if self.type == 'matching':
            try:
                return json.loads(self.correct_answer)
            except (json.JSONDecodeError, TypeError):
                return []
        return []

class AssessmentResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    block_id = db.Column(db.Integer, db.ForeignKey('assessment_block.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    answers = db.Column(db.String(5000))  # JSON string storing user's answers
    
    # Определяем связи
    block = db.relationship('AssessmentBlock', backref='results')
    user = db.relationship('User', backref='assessment_results')

class PeerEvaluation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evaluator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    evaluated_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

class WorkGroupEvaluation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evaluator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    evaluated_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    criteria_scores = db.Column(db.String(1000))  # JSON string storing scores for each criterion
    date = db.Column(db.DateTime, default=datetime.utcnow)

class ExpertCodeEvaluation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assessment_result_id = db.Column(db.Integer, db.ForeignKey('assessment_result.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('assessment_question.id'), nullable=False)
    expert_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    comments = db.Column(db.String(1000))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    assessment_result = db.relationship('AssessmentResult', backref='expert_evaluations')
    question = db.relationship('AssessmentQuestion')
    expert = db.relationship('User')

class ExpertAnswerHistory(db.Model):
    """Модель для хранения истории ответов экспертов"""
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('assessment_question.id'), nullable=False)
    expert_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    answer = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Связи
    question = db.relationship('AssessmentQuestion')
    expert = db.relationship('User')

# Декораторы
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def sync_session_role():
    """Synchronize the session role with the database role"""
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and session.get('role') != user.role:
            session['role'] = user.role
            debug_print(f"Synchronized session role to {user.role} for user {user.username}")

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Пожалуйста, войдите в систему', 'error')
                return redirect(url_for('login'))
            
            # Sync session role with database role
            sync_session_role()
            
            user = User.query.get(session['user_id'])
            if user.role not in roles:
                flash('У вас нет прав для доступа к этой странице', 'error')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.before_request
def before_request():
    """Middleware для синхронизации user_id в сессии с Flask-Login"""
    try:
        # Если пользователь аутентифицирован через Flask-Login, но нет user_id в сессии,
        # обновляем сессию
        if current_user.is_authenticated and ('user_id' not in session or session.get('user_id') != current_user.id):
            session['user_id'] = current_user.id
            session['role'] = current_user.role
            session['username'] = current_user.username
            debug_print(f"Синхронизирована сессия с Flask-Login: user_id={current_user.id}")
        
        # Если есть user_id в сессии, но пользователь не аутентифицирован через Flask-Login,
        # пытаемся восстановить аутентификацию
        elif 'user_id' in session and not current_user.is_authenticated:
            user = User.query.get(session['user_id'])
            if user:
                login_user(user)
                debug_print(f"Восстановлена аутентификация из сессии: user_id={user.id}")
    except Exception as e:
        debug_print(f"Ошибка синхронизации аутентификации: {str(e)}")

# Маршруты
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Имя пользователя и пароль обязательны', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'error')
            return redirect(url_for('register'))
        
        new_user = User(username=username, role='user')
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            session['role'] = new_user.role
            session['username'] = new_user.username
            flash('Регистрация успешна! Добро пожаловать!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при регистрации: {str(e)}', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Введите имя пользователя и пароль', 'error')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        debug_print(f"Попытка входа пользователя: {username}")
        
        if user and user.check_password(password):
            debug_print(f"Успешный вход. Роль пользователя: {user.role}")
            
            # Ensure user has a valid role
            if not user.role:
                user.role = 'user'
                db.session.commit()
                debug_print(f"Установлена роль по умолчанию для пользователя {user.username}")
            
            login_user(user)  # Используем login_user из Flask-Login
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            debug_print(f"Сессия установлена: user_id={session['user_id']}, role={session['role']}, username={session['username']}")
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('index'))
        
        flash('Неверное имя пользователя или пароль', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Используем logout_user из Flask-Login
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    debug_print(f"Профиль пользователя: id={user.id}, username={user.username}, role={user.role}")
    
    # Проверяем, что роль пользователя корректно установлена
    if not user.role:
        debug_print("Роль пользователя не установлена, устанавливаем значение по умолчанию")
        user.role = 'user'
        db.session.commit()
    
    # Получаем все результаты оценки пользователя
    assessment_results = AssessmentResult.query.filter_by(user_id=user.id).all()
    
    # Получаем все блоки оценки
    blocks = {block.id: block for block in AssessmentBlock.query.all()}
    
    # Создаем список с результатами по блокам
    block_results = []
    normalized_scores = {}
    
    for block in blocks.values():
        result = AssessmentResult.query.filter_by(
            user_id=user.id,
            block_id=block.id
        ).order_by(AssessmentResult.date.desc()).first()
        
        # Нормализуем оценку относительно максимального балла блока
        if result:
            normalized_score = min(1.0, result.score / block.max_score)
            normalized_scores[block.id] = normalized_score
            score_percentage = normalized_score * 100
        else:
            normalized_scores[block.id] = 0
            score_percentage = 0
        
        block_results.append({
            'block': block,
            'result': result,
            'score_percentage': score_percentage
        })
    
    # Рассчитываем итоговую оценку
    final_score_data = calculate_final_score(user.id)
    
    debug_print(f"Отображаемая роль пользователя: {user.role_display}")
    
    return render_template('profile.html',
                         user=user,
                         block_results=block_results,
                         final_score=final_score_data)

@app.route('/manage_users')
@role_required(['admin'])
def manage_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/update_user/<int:user_id>', methods=['POST'])
@role_required(['admin'])
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role in ['user', 'expert', 'admin', 'working_group']:
        user.role = new_role
        db.session.commit()
        
        # Update session role if the user is updating their own role
        if user_id == session.get('user_id'):
            session['role'] = new_role
            debug_print(f"Updated session role to {new_role} for user {user.username}")
        
        flash(f'Роль пользователя {user.username} обновлена на {new_role}', 'success')
    else:
        flash('Недопустимая роль', 'error')
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@role_required(['admin'])
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('Вы не можете удалить себя', 'error')
        return redirect(url_for('manage_users'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Пользователь успешно удален', 'success')
    return redirect(url_for('manage_users'))

@app.route('/manage_questions')
@role_required(['expert', 'admin'])
def manage_questions():
    questions = Question.query.all()
    return render_template('questions.html', questions=questions)

@app.route('/add_question', methods=['GET', 'POST'])
@role_required(['expert', 'admin'])
def add_question():
    if request.method == 'POST':
        try:
            print("DEBUG: Получен POST запрос")
            print("DEBUG: Форма:", request.form)
            print("DEBUG: Файлы:", request.files)
            
            question_type = request.form['type']
            question_text = request.form['question_text']
            
            if not question_text:
                flash('Текст вопроса не может быть пустым', 'error')
                return redirect(url_for('add_question'))
            
            if question_type == 'regular':
                options = request.form.getlist('regular_options[]')
                correct_indices = request.form.getlist('correct_answers[]')
                
                print(f"DEBUG: Получены варианты ответов: {options}")
                print(f"DEBUG: Получены индексы правильных ответов: {correct_indices}")
                
                if not options:
                    flash('Необходимо добавить варианты ответов', 'error')
                    return redirect(url_for('add_question'))
                
                if not correct_indices:
                    flash('Необходимо выбрать правильный ответ', 'error')
                    return redirect(url_for('add_question'))
                
                # Получаем правильные ответы по индексам
                correct_answers = []
                for index in correct_indices:
                    try:
                        idx = int(index) - 1  # Индексы начинаются с 1
                        if 0 <= idx < len(options):
                            correct_answers.append(options[idx])
                    except ValueError:
                        continue
                
                if not correct_answers:
                    flash('Ошибка в выборе правильных ответов', 'error')
                    return redirect(url_for('add_question'))
                
                print(f"DEBUG: Правильные ответы: {correct_answers}")
                
                # Обработка изображения
                image = request.files.get('regular_image')
                image_path = None
                if image and image.filename:
                    filename = f"question_{datetime.now().strftime('%Y%m%d%H%M%S')}_{image.filename}"
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    image_path = filename
                    print(f"DEBUG: Сохранено изображение: {filename}")
                
                new_question = Question(
                    type=question_type,
                    text=question_text,
                    options=json.dumps(options),
                    correct_answer=json.dumps(correct_answers),
                    image_path=image_path
                )
                
            else:  # association
                associations = request.form.get('association_answers', '').strip()
                if not associations:
                    flash('Необходимо указать ассоциации', 'error')
                    return redirect(url_for('add_question'))
                
                associations_list = [a.strip() for a in associations.split(',') if a.strip()]
                required_matches = int(request.form.get('association_matches', 1))
                
                print(f"DEBUG: Ассоциации: {associations_list}")
                print(f"DEBUG: Требуемое количество совпадений: {required_matches}")
                
                if not associations_list:
                    flash('Необходимо указать хотя бы одну ассоциацию', 'error')
                    return redirect(url_for('add_question'))
                
                if required_matches < 1 or required_matches > len(associations_list):
                    flash('Некорректное количество требуемых совпадений', 'error')
                    return redirect(url_for('add_question'))
                
                # Обработка изображения
                image = request.files.get('association_image')
                image_path = None
                if image and image.filename:
                    filename = f"question_{datetime.now().strftime('%Y%m%d%H%M%S')}_{image.filename}"
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    image_path = filename
                    print(f"DEBUG: Сохранено изображение: {filename}")
                
                new_question = Question(
                    type=question_type,
                    text=question_text,
                    options=json.dumps(associations_list),
                    required_matches=required_matches,
                    image_path=image_path
                )
            
            print("DEBUG: Добавление вопроса в базу данных")
            db.session.add(new_question)
            db.session.commit()
            print("DEBUG: Вопрос успешно добавлен")
            
            flash('Вопрос успешно добавлен', 'success')
            return redirect(url_for('manage_questions'))
            
        except Exception as e:
            db.session.rollback()
            print(f"DEBUG: Ошибка при добавлении вопроса: {str(e)}")
            import traceback
            print("DEBUG: Трейс ошибки:")
            print(traceback.format_exc())
            flash(f'Ошибка при добавлении вопроса: {str(e)}', 'error')
            return redirect(url_for('add_question'))
    
    return render_template('add_question.html')

@app.route('/edit_question/<int:question_id>', methods=['GET', 'POST'])
@role_required(['expert', 'admin'])
def edit_question(question_id):
    question = Question.query.get_or_404(question_id)
    
    if request.method == 'POST':
        question.text = request.form['question_text']
        
        if question.type == 'regular':
            options = request.form.getlist('options[]')
            question.options = json.dumps(options)
            question.correct_answer = request.form['correct_answer']
        else:  # association
            image = request.files.get('image')
            if image:
                if question.image_path:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], question.image_path)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                filename = f"question_{datetime.now().strftime('%Y%m%d%H%M%S')}_{image.filename}"
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                question.image_path = filename
            
            associations = request.form.getlist('associations[]')
            question.options = json.dumps(associations)
            question.required_matches = int(request.form['required_matches'])
        
        db.session.commit()
        flash('Вопрос успешно обновлен', 'success')
        return redirect(url_for('manage_questions'))
    
    return render_template('edit_question.html', question=question)

@app.route('/delete_question/<int:question_id>', methods=['POST'])
@role_required(['expert', 'admin'])
def delete_question(question_id):
    question = Question.query.get_or_404(question_id)
    
    if question.image_path:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], question.image_path)
        if os.path.exists(image_path):
            os.remove(image_path)
    
    db.session.delete(question)
    db.session.commit()
    flash('Вопрос успешно удален', 'success')
    return redirect(url_for('manage_questions'))

@app.route('/quiz')
@login_required
def quiz():
    questions = Question.query.all()
    return render_template('quiz.html', questions=questions)

@app.route('/submit_quiz', methods=['POST'])
@login_required
def submit_quiz():
    total_questions = Question.query.count()
    correct_answers = 0
    questions_with_answers = []
    
    for question in Question.query.all():
        if question.type == 'regular':
            # Проверяем, один или несколько правильных ответов
            if len(question.get_correct_answers()) > 1:
                # Множественный выбор - получаем список ответов
                answers = request.form.getlist(f'answer_{question.id}[]')
                is_correct = question.check_answer(answers)
            else:
                # Единственный выбор
                answer = request.form.get(f'answer_{question.id}')
                is_correct = question.check_answer(answer)
                answers = [answer] if answer else []
            
            if is_correct:
                correct_answers += 1
            questions_with_answers.append((question, answers, is_correct))
        
        elif question.type == 'association':
            # Получаем строку с ассоциациями
            answer = request.form.get(f'answer_{question.id}', '').strip()
            is_correct = question.check_answer(answer)
            if is_correct:
                correct_answers += 1
            questions_with_answers.append((question, answer.split(','), is_correct))
    
    score = (correct_answers / total_questions) * 100 if total_questions > 0 else 0
    result = Result(user_id=session['user_id'], score=score)
    db.session.add(result)
    db.session.commit()
    
    return render_template('quiz_results.html', 
                         score=score,
                         correct_answers=correct_answers,
                         total_questions=total_questions,
                         questions_with_answers=questions_with_answers)

@app.route('/results')
@login_required
def results():
    results = Result.query.filter_by(user_id=session['user_id']).order_by(Result.date.desc()).all()
    return render_template('results.html', results=results)

@app.route('/admin/change_password/<int:user_id>', methods=['POST'])
@role_required(['admin'])
def admin_change_password(user_id):
    user = User.query.get_or_404(user_id)
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    # Проверяем, является ли целевой пользователь первым администратором
    first_admin = User.query.filter_by(role='admin').order_by(User.id).first()
    if user.id == first_admin.id and session['user_id'] != first_admin.id:
        flash('Только первый администратор может изменить свой пароль', 'error')
        return redirect(url_for('manage_users'))
    
    if new_password != confirm_password:
        flash('Пароли не совпадают', 'error')
        return redirect(url_for('manage_users'))
    
    if not new_password:
        flash('Новый пароль не может быть пустым', 'error')
        return redirect(url_for('manage_users'))
    
    user.set_password(new_password)
    db.session.commit()
    flash(f'Пароль пользователя {user.username} успешно изменен', 'success')
    return redirect(url_for('manage_users'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        user = User.query.get(session['user_id'])
        
        # Проверяем текущий пароль
        if not check_password_hash(user.password, current_password):
            flash('Текущий пароль неверен', 'error')
            return redirect(url_for('change_password'))
        
        # Проверяем, что новый пароль отличается от текущего
        if check_password_hash(user.password, new_password):
            flash('Новый пароль должен отличаться от текущего', 'error')
            return redirect(url_for('change_password'))
        
        # Проверяем совпадение нового пароля и подтверждения
        if new_password != confirm_password:
            flash('Новые пароли не совпадают', 'error')
            return redirect(url_for('change_password'))
        
        # Проверяем, что новый пароль не пустой
        if not new_password:
            flash('Новый пароль не может быть пустым', 'error')
            return redirect(url_for('change_password'))
        
        user.set_password(new_password)
        db.session.commit()
        flash('Пароль успешно изменен', 'success')
        return redirect(url_for('profile'))
    
    return render_template('change_password.html')

def create_test_questions():
    # Проверяем, есть ли уже вопросы в базе
    if Question.query.first() is not None:
        return

    questions = [
 
    ]

    for q in questions:
        question = Question(
            type=q['type'],
            text=q['text'],
            options=q['options'],
            correct_answer=q.get('correct_answer'),
            required_matches=q.get('required_matches'),
            image_path=q['image_path']
        )
        db.session.add(question)

    db.session.commit()

@app.route('/assessment_blocks')
@role_required(['expert', 'admin'])
def assessment_blocks():
    blocks = AssessmentBlock.query.all()
    return render_template('assessment_blocks.html', blocks=blocks)

@app.route('/add_assessment_block', methods=['GET', 'POST'])
@role_required(['expert', 'admin'])
def add_assessment_block():
    if request.method == 'POST':
        name = request.form['name']
        weight = float(request.form['weight'])
        max_score = float(request.form['max_score'])
        
        new_block = AssessmentBlock(name=name, weight=weight, max_score=max_score)
        db.session.add(new_block)
        db.session.commit()
        
        flash('Блок оценки успешно добавлен', 'success')
        return redirect(url_for('assessment_blocks'))
    
    return render_template('add_assessment_block.html')

@app.route('/edit_assessment_block/<int:block_id>', methods=['GET', 'POST'])
@role_required(['expert', 'admin'])
def edit_assessment_block(block_id):
    block = AssessmentBlock.query.get_or_404(block_id)
    
    if request.method == 'POST':
        block.name = request.form['name']
        block.weight = float(request.form['weight'])
        block.max_score = float(request.form['max_score'])
        
        db.session.commit()
        flash('Блок оценки успешно обновлен', 'success')
        return redirect(url_for('assessment_blocks'))
    
    return render_template('edit_assessment_block.html', block=block)

@app.route('/delete_assessment_block/<int:block_id>', methods=['POST'])
@role_required(['expert', 'admin'])
def delete_assessment_block(block_id):
    try:
        block = AssessmentBlock.query.get_or_404(block_id)
        # Удаляем все вопросы этого блока
        for question in AssessmentQuestion.query.filter_by(block_id=block.id).all():
            db.session.delete(question)
        db.session.delete(block)
        db.session.commit()
        flash('Блок оценки успешно удален', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении блока: {str(e)}', 'error')
    return redirect(url_for('assessment_blocks'))

@app.route('/assessment_questions/<int:block_id>')
@role_required(['expert', 'admin'])
def assessment_questions(block_id):
    block = AssessmentBlock.query.get_or_404(block_id)
    questions = AssessmentQuestion.query.filter_by(block_id=block_id).all()
    return render_template('assessment_questions.html', block=block, questions=questions)

@app.route('/add_assessment_question/<int:block_id>', methods=['GET', 'POST'])
@role_required(['expert', 'admin'])
def add_assessment_question(block_id):
    block = AssessmentBlock.query.get_or_404(block_id)
    
    if request.method == 'POST':
        question_type = request.form['type']
        text = request.form['text']
        points = float(request.form['points'])
        
        options = None
        correct_answer = None
        code_template = None
        test_cases = None
        
        if question_type in ['single', 'multiple']:
            options = json.dumps(request.form.getlist('options[]'))
            correct_answer = json.dumps(request.form.getlist('correct_answers[]'))
        elif question_type == 'code':
            code_template = request.form['code_template']
            test_cases = json.dumps(request.form.getlist('test_cases[]'))
        else:  # open question
            correct_answer = json.dumps(request.form['correct_answer'])
        
        new_question = AssessmentQuestion(
            block_id=block_id,
            type=question_type,
            text=text,
            options=options,
            correct_answer=correct_answer,
            points=points,
            code_template=code_template,
            test_cases=test_cases
        )
        
        db.session.add(new_question)
        db.session.commit()
        
        flash('Вопрос успешно добавлен', 'success')
        return redirect(url_for('assessment_questions', block_id=block_id))
    
    return render_template('add_assessment_question.html', block=block)

@app.route('/edit_assessment_question/<int:question_id>', methods=['GET', 'POST'])
@role_required(['expert', 'admin'])
def edit_assessment_question(question_id):
    question = AssessmentQuestion.query.get_or_404(question_id)
    block = question.block
    
    if request.method == 'POST':
        question.type = request.form['type']
        question.text = request.form['text']
        question.points = float(request.form['points'])
        
        if question.type in ['single', 'multiple']:
            question.options = json.dumps(question.options)
            question.correct_answer = json.dumps(question.correct_answer)
            question.code_template = None
            question.test_cases = None
        elif question.type == 'code':
            question.options = None
            question.correct_answer = None
            question.code_template = request.form['code_template']
            question.test_cases = json.dumps(question.test_cases)
        else:  # open question
            question.options = None
            question.correct_answer = json.dumps(question.correct_answer)
            question.code_template = None
            question.test_cases = None
        
        db.session.commit()
        flash('Вопрос успешно обновлен', 'success')
        return redirect(url_for('assessment_questions', block_id=block.id))
    
    return render_template('edit_assessment_question.html', question=question, block=block)

@app.route('/delete_assessment_question/<int:question_id>', methods=['POST'])
@role_required(['expert', 'admin'])
def delete_assessment_question(question_id):
    question = AssessmentQuestion.query.get_or_404(question_id)
    block_id = question.block_id
    db.session.delete(question)
    db.session.commit()
    flash('Вопрос успешно удален', 'success')
    return redirect(url_for('assessment_questions', block_id=block_id))

@app.route('/take_assessment')
@login_required
def take_assessment():
    blocks = AssessmentBlock.query.all()
    return render_template('take_assessment.html', blocks=blocks)

@app.route('/submit_assessment_block/<int:block_id>', methods=['GET', 'POST'])
@login_required
def submit_assessment_block(block_id):
    """Обработка отправки ответов на блок оценки, включая взаимооценку для блока 4"""
    block = AssessmentBlock.query.get_or_404(block_id)
    questions = AssessmentQuestion.query.filter_by(block_id=block_id).all()

    # Взаимооценка — особый случай для блока 4
    if block.name == 'Взаимооценка':
        users_all = User.query.all()
        experts = User.query.filter(
            User.role == 'expert',
            User.id != current_user.id,
            User.username != 'admin'
        ).all()
        previous_evaluations = {}
        for eval in PeerEvaluation.query.filter_by(evaluator_id=current_user.id).all():
            previous_evaluations[eval.evaluated_id] = {'score': eval.score}
        debug_print(f"[B4] current_user = {getattr(current_user, 'id', None)}, {getattr(current_user, 'username', None)}, {getattr(current_user, 'role', None)}")
        debug_print(f"[B4] users_all = {[f'{u.id}|{u.username}|{u.role}' for u in users_all]}")
        debug_print(f"[B4] experts = {[f'{u.id}|{u.username}|{u.role}' for u in experts]}")
        debug_print(f"[B4] previous_evaluations = {previous_evaluations}")

        if request.method == 'POST':
            # Удаляем предыдущие оценки текущего пользователя
            PeerEvaluation.query.filter_by(evaluator_id=current_user.id).delete()
            # Сохраняем новые оценки
            for expert in experts:
                score = request.form.get(f'score_{expert.id}')
                if score is not None:
                    try:
                        score = float(score)
                        if 0 <= score <= 10:
                            evaluation = PeerEvaluation(
                                evaluator_id=current_user.id,
                                evaluated_id=expert.id,
                                score=score
                            )
                            db.session.add(evaluation)
                    except ValueError:
                        flash(f'Некорректная оценка для эксперта {expert.username}', 'error')
                        continue
            db.session.commit()
            flash('Оценки успешно сохранены', 'success')
            return redirect(url_for('assessment_results'))
        # GET — показать таблицу экспертов
        return render_template('peer_evaluation.html',
                             experts=experts,
                             previous_evaluations=previous_evaluations,
                             users_all=users_all)

    # Обычная обработка для других блоков
    if request.method == 'POST':
        try:
            answers = {}
            total_score = 0
            has_answers = False
            
            for question in questions:
                if question.type == 'single':
                    answer = request.form.get(f'answer_{question.id}')
                    if answer is not None:
                        has_answers = True
                        answers[str(question.id)] = int(answer)
                        if question.option_scores:
                            scores = json.loads(question.option_scores)
                            total_score += scores[int(answer)] * question.weight if question.weight else scores[int(answer)]
                        else:
                            # Если нет option_scores, даем баллы за любой ответ
                            total_score += question.points * (question.weight if question.weight else 1)
                            
                elif question.type == 'multiple':
                    selected_options = request.form.getlist(f'answer_{question.id}')
                    if selected_options:
                        has_answers = True
                        answers[str(question.id)] = [int(opt) for opt in selected_options]
                        # Обработка баллов для multiple choice
                        if question.option_scores:
                            scores = json.loads(question.option_scores)
                            for opt in selected_options:
                                total_score += scores[int(opt)] * question.weight if question.weight else scores[int(opt)]
                        else:
                            # Если нет option_scores, даем баллы за любой ответ
                            total_score += question.points * (question.weight if question.weight else 1)
                            
                elif question.type == 'matching':
                    matches = request.form.getlist(f'answer_{question.id}[]')
                    if matches:
                        has_answers = True
                        answers[str(question.id)] = matches
                        
                        # Проверяем правильность сопоставлений
                        correct_matches = question.get_correct_matches()
                        if correct_matches:
                            correct_count = sum(1 for i, m in enumerate(matches) if i < len(correct_matches) and m == correct_matches[i])
                            score = (correct_count / len(correct_matches)) * question.points
                            total_score += score * (question.weight if question.weight else 1)
                        else:
                            # Если нет correct_matches, даем баллы за любой ответ
                            total_score += question.points * (question.weight if question.weight else 1)
                            
                elif question.type == 'code':
                    code = request.form.get(f'answer_{question.id}')
                    if code and code.strip():
                        has_answers = True
                        answers[str(question.id)] = code
                        # Баллы за код будут выставлены экспертами позже
                        # Временно даем небольшой балл за заполнение
                        total_score += 1
                        
                elif question.type == 'expert_evaluation':
                    criteria = question.get_criteria()
                    question_scores = []
                    all_criteria_answered = True
                    
                    for i, criterion in enumerate(criteria):
                        score_str = request.form.get(f'criterion_{question.id}_{i+1}')
                        if not score_str:
                            all_criteria_answered = False
                            break
                        score = float(score_str)
                        question_scores.append(score)
                    
                    if all_criteria_answered and question_scores:
                        has_answers = True
                        answers[str(question.id)] = question_scores
                        avg_score = sum(question_scores) / len(question_scores)
                        total_score += avg_score * question.weight if question.weight else avg_score
                
                # Для любых других типов вопросов
                else:
                    answer = request.form.get(f'answer_{question.id}')
                    if answer and answer.strip():
                        has_answers = True
                        answers[str(question.id)] = answer
                        # Даем баллы за заполнение
                        total_score += question.points * (question.weight if question.weight else 1)
            
            if not has_answers:
                flash('Пожалуйста, ответьте хотя бы на один вопрос', 'error')
                return render_template('assessment_block.html', block=block, questions=questions)
                
            result = AssessmentResult(
                user_id=current_user.id,
                block_id=block_id,
                score=total_score,
                answers=json.dumps(answers)
            )
            db.session.add(result)
            db.session.commit()
            flash('Ответы успешно сохранены', 'success')
            return redirect(url_for('assessment_results'))
        except Exception as e:
            debug_print(f"Ошибка при сохранении ответов: {str(e)}")
            db.session.rollback()
            flash('Произошла ошибка при сохранении ответов', 'error')
    return render_template('assessment_block.html', block=block, questions=questions)

@app.route('/expert/code_evaluations')
@role_required(['expert', 'admin'])
def expert_code_evaluations():
    """Страница для экспертов по оценке кода"""
    try:
        debug_print("Начинаем загрузку кодов для оценки...")
        
        # Получаем все результаты с кодовыми вопросами, исключая свои
        results = AssessmentResult.query\
            .join(AssessmentBlock)\
            .join(AssessmentQuestion)\
            .filter(AssessmentQuestion.type == 'code')\
            .filter(AssessmentResult.user_id != current_user.id)\
            .all()
        
        debug_print(f"Найдено результатов: {len(results)}")
        
        # Группируем по блокам
        blocks_data = {}
        for result in results:
            try:
                answers = json.loads(result.answers)
                block = result.block
                debug_print(f"Результат: id={result.id}, user_id={result.user_id}, block={block.name}")
                if block.id not in blocks_data:
                    blocks_data[block.id] = {
                        'block': block,
                        'evaluations': []
                    }
                for question in block.questions:
                    debug_print(f"Проверяем вопрос: id={question.id}, type={question.type}")
                    if question.type == 'code':
                        user_code = answers.get(str(question.id), '')
                        debug_print(f"user_code для question {question.id}: '{user_code}'")
                        if user_code and user_code.strip():
                            is_evaluated = ExpertCodeEvaluation.query.filter_by(
                                assessment_result_id=result.id,
                                question_id=question.id,
                                expert_id=current_user.id
                            ).first() is not None
                            debug_print(f"is_evaluated={is_evaluated}")
                            if not is_evaluated:
                                blocks_data[block.id]['evaluations'].append({
                                    'result': result,
                                    'question': question,
                                    'user_code': user_code,
                                    'block': block,
                                    'is_evaluated': is_evaluated
                                })
                                debug_print(f"Добавлен код для оценки: блок {block.name}, вопрос {question.id}")
            except json.JSONDecodeError as e:
                debug_print(f"Ошибка при разборе JSON для результата {result.id}: {str(e)}")
                continue
        debug_print(f"Подготовлено блоков для оценки: {len(blocks_data)}")
        for block_id, data in blocks_data.items():
            debug_print(f"Блок {block_id} содержит {len(data['evaluations'])} заданий для оценки")
        return render_template('expert_code_evaluations.html', blocks_data=blocks_data)
    except Exception as e:
        debug_print(f"Ошибка при загрузке кодов для проверки: {str(e)}")
        flash(f'Ошибка при загрузке кодов для проверки: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/evaluate_code/<int:result_id>/<int:question_id>', methods=['GET', 'POST'])
@role_required(['expert', 'admin'])
def evaluate_code(result_id, question_id):
    """Оценка кода пользователя"""
    # Проверяем, что эксперт не оценивает свой код
    result = AssessmentResult.query.get_or_404(result_id)
    if result.user_id == current_user.id:
        flash('Вы не можете оценивать свой код', 'error')
        return redirect(url_for('expert_code_evaluations'))
    
    question = AssessmentQuestion.query.get_or_404(question_id)
    
    if question.type != 'code':
        flash('Этот вопрос не является кодом', 'error')
        return redirect(url_for('expert_code_evaluations'))
    
    # Получаем код пользователя
    try:
        answers = json.loads(result.answers)
        code = answers.get(str(question.id), '')
    except json.JSONDecodeError:
        flash('Ошибка при чтении ответов', 'error')
        return redirect(url_for('expert_code_evaluations'))
    
    # Получаем примеры решений
    example_solutions = []
    if question.example_solutions:
        try:
            example_solutions = json.loads(question.example_solutions)
        except json.JSONDecodeError:
            pass
    
    # Тестируем код
    test_results = []
    test_success = False
    if code:
        test_results, test_success = test_code_submission(code, json.loads(question.test_cases))
    
    # Получаем существующую оценку
    existing_evaluation = ExpertCodeEvaluation.query.filter_by(
        assessment_result_id=result_id,
        question_id=question_id,
        expert_id=current_user.id
    ).first()
    
    # Получаем предыдущие оценки
    previous_evaluations = ExpertCodeEvaluation.query.filter_by(
        assessment_result_id=result_id,
        question_id=question_id
    ).order_by(ExpertCodeEvaluation.date.desc()).all()
    
    if request.method == 'POST':
        score = float(request.form['score'])
        comments = request.form['comments']
        
        if existing_evaluation:
            existing_evaluation.score = score
            existing_evaluation.comments = comments
        else:
            evaluation = ExpertCodeEvaluation(
                assessment_result_id=result_id,
                question_id=question_id,
                expert_id=current_user.id,
                score=score,
                comments=comments
            )
            db.session.add(evaluation)
        
        db.session.commit()
        flash('Оценка сохранена', 'success')
        return redirect(url_for('expert_code_evaluations'))
    
    return render_template('evaluate_code.html',
                         result=result,
                         question=question,
                         code=code,
                         test_results=test_results,
                         test_success=test_success,
                         existing_evaluation=existing_evaluation,
                         previous_evaluations=previous_evaluations,
                         example_solutions=example_solutions)

@app.route('/expert/text_evaluations')
@role_required(['expert', 'admin'])
def expert_text_evaluations():
    """Страница для экспертов по оценке текстовых ответов"""
    try:
        # Получаем все результаты с текстовыми вопросами, исключая свои
        results = AssessmentResult.query\
            .join(AssessmentBlock)\
            .join(AssessmentQuestion)\
            .filter(AssessmentQuestion.type.in_(['open', 'single', 'multiple']))\
            .filter(AssessmentResult.user_id != current_user.id)\
            .all()
        
        # Группируем по блокам
        blocks_data = {}
        for result in results:
            try:
                answers = json.loads(result.answers)
                block = result.block
                
                if block.id not in blocks_data:
                    blocks_data[block.id] = {
                        'block': block,
                        'evaluations': []
                    }
                
                for question in block.questions:
                    if question.type in ['open', 'single', 'multiple']:
                        # Создаем уникальный идентификатор для анонимизации
                        evaluation_id = f"eval_{result.id}_{question.id}"
                        
                        blocks_data[block.id]['evaluations'].append({
                            'evaluation_id': evaluation_id,
                            'result': result,
                            'question': question,
                            'user_answer': answers.get(str(question.id), ''),
                            'block': block,
                            'is_evaluated': ExpertCodeEvaluation.query.filter_by(
                                assessment_result_id=result.id,
                                question_id=question.id
                            ).first() is not None
                        })
            except json.JSONDecodeError:
                continue
        
        return render_template('expert_text_evaluations.html', blocks_data=blocks_data)
    except Exception as e:
        flash(f'Ошибка при загрузке ответов для проверки: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/evaluate_text/<int:result_id>/<int:question_id>', methods=['GET', 'POST'])
@role_required(['expert', 'admin'])
def evaluate_text(result_id, question_id):
    """Оценка текстового ответа пользователя"""
    # Проверяем, что эксперт не оценивает свой ответ
    result = AssessmentResult.query.get_or_404(result_id)
    if result.user_id == current_user.id:
        flash('Вы не можете оценивать свои ответы', 'error')
        return redirect(url_for('expert_text_evaluations'))
    
    question = AssessmentQuestion.query.get_or_404(question_id)
    
    if question.type not in ['open', 'single', 'multiple']:
        flash('Этот вопрос не является текстовым', 'error')
        return redirect(url_for('expert_text_evaluations'))
    
    # Получаем ответ пользователя
    try:
        answers = json.loads(result.answers)
        user_answer = answers.get(str(question.id), '')
    except json.JSONDecodeError:
        flash('Ошибка при чтении ответов', 'error')
        return redirect(url_for('expert_text_evaluations'))
    
    # Получаем существующую оценку
    existing_evaluation = ExpertCodeEvaluation.query.filter_by(
        assessment_result_id=result_id,
        question_id=question_id,
        expert_id=current_user.id
    ).first()
    
    # Получаем предыдущие оценки
    previous_evaluations = ExpertCodeEvaluation.query.filter_by(
        assessment_result_id=result_id,
        question_id=question_id
    ).order_by(ExpertCodeEvaluation.date.desc()).all()
    
    if request.method == 'POST':
        score = float(request.form['score'])
        comments = request.form['comments']
        
        if existing_evaluation:
            existing_evaluation.score = score
            existing_evaluation.comments = comments
        else:
            evaluation = ExpertCodeEvaluation(
                assessment_result_id=result_id,
                question_id=question_id,
                expert_id=current_user.id,
                score=score,
                comments=comments
            )
            db.session.add(evaluation)
        
        db.session.commit()
        flash('Оценка сохранена', 'success')
        return redirect(url_for('expert_text_evaluations'))
    
    return render_template('evaluate_text.html',
                         result=result,
                         question=question,
                         user_answer=user_answer,
                         existing_evaluation=existing_evaluation,
                         previous_evaluations=previous_evaluations)

def test_code_submission(code, test_cases):
    """Тестирует код пользователя на тестовых случаях"""
    try:
        # Создаем временный файл для кода
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        # Запускаем тесты
        test_results = []
        all_passed = True
        
        for test in test_cases:
            input_data = test['input']
            expected = test['expected']
            
            try:
                # Запускаем код с входными данными
                result = subprocess.run(['node', temp_file], 
                                     input=str(input_data).encode(),
                                     capture_output=True,
                                     text=True,
                                     timeout=5)
                
                if result.returncode == 0:
                    actual = result.stdout.strip()
                    passed = str(actual) == str(expected)
                    test_results.append({
                        'input': input_data,
                        'expected': expected,
                        'actual': actual,
                        'passed': passed
                    })
                    if not passed:
                        all_passed = False
                else:
                    test_results.append({
                        'input': input_data,
                        'expected': expected,
                        'error': result.stderr,
                        'passed': False
                    })
                    all_passed = False
            except subprocess.TimeoutExpired:
                test_results.append({
                    'input': input_data,
                    'expected': expected,
                    'error': 'Timeout',
                    'passed': False
                })
                all_passed = False
            except Exception as e:
                test_results.append({
                    'input': input_data,
                    'expected': expected,
                    'error': str(e),
                    'passed': False
                })
                all_passed = False
        
        # Если все тесты пройдены, сохраняем решение как пример
        if all_passed:
            question = AssessmentQuestion.query.filter_by(test_cases=json.dumps(test_cases)).first()
            if question:
                example_solutions = []
                if question.example_solutions:
                    try:
                        example_solutions = json.loads(question.example_solutions)
                    except json.JSONDecodeError:
                        pass
                
                # Добавляем новое решение, если его еще нет
                if code not in example_solutions:
                    example_solutions.append(code)
                    question.example_solutions = json.dumps(example_solutions)
                    db.session.commit()
        
        return test_results, all_passed
    except Exception as e:
        return [{'error': str(e)}], False
    finally:
        # Удаляем временный файл
        try:
            os.unlink(temp_file)
        except:
            pass

def calculate_final_score(user_id):
    """Рассчитывает итоговую оценку пользователя"""
    try:
        # Получаем все результаты оценки пользователя
        assessment_results = AssessmentResult.query.filter_by(user_id=user_id).all()
        
        # Получаем все блоки
        blocks = {block.id: block for block in AssessmentBlock.query.all()}
        
        # Словарь для хранения нормализованных оценок по каждому блоку
        normalized_scores = {}
        total_weight = 0
        weighted_sum = 0
        
        # Рассчитываем оценки по каждому блоку
        for result in assessment_results:
            block = blocks.get(result.block_id)
            if block:
                # Нормализуем оценку относительно максимального балла блока
                normalized_score = min(1.0, result.score / block.max_score)
                normalized_scores[block.id] = normalized_score
                
                # Учитываем вес блока в итоговой оценке
                weighted_sum += normalized_score * block.weight
                total_weight += block.weight
        
        # Рассчитываем итоговую оценку (от 0 до 1)
        final_score = (weighted_sum / total_weight) if total_weight > 0 else 0
        
        # Определяем уровень компетентности по новой шкале
        if final_score == 0:
            level = "Некомпетентен"
        elif final_score <= 0.15:
            level = "Некомпетентен"
        elif final_score <= 0.4:
            level = "Низкий уровень"
        elif final_score <= 0.6:
            level = "Средний уровень"
        elif final_score <= 0.8:
            level = "Выше среднего"
        elif final_score < 1:
            level = "Высокий уровень"
        else:
            level = "Максимальная компетентность"
        
        return {
            'final_score': final_score * 100,  # Переводим в проценты для отображения
            'level': level,
            'normalized_scores': normalized_scores
        }
        
    except Exception as e:
        print(f"Ошибка при расчете итоговой оценки: {str(e)}")
        return {
            'final_score': 0,
            'level': "Некомпетентен",
            'normalized_scores': {}
        }

@app.route('/assessment_results')
@login_required
def assessment_results():
    """Отображает результаты оценки и взаимооценки для текущего пользователя"""
    try:
        if not current_user.is_authenticated:
            flash('Для просмотра результатов необходимо авторизоваться', 'error')
            return redirect(url_for('login'))
            
        debug_print(f"Начало обработки результатов для пользователя {current_user.id}")
        
        # Получаем все блоки оценки
        blocks = AssessmentBlock.query.all()
        debug_print(f"Найдено блоков оценки: {len(blocks)}")
        
        # Получаем результаты оценки для текущего пользователя
        assessment_results = AssessmentResult.query.filter_by(user_id=current_user.id).all()
        debug_print(f"Найдено результатов оценки: {len(assessment_results)}")
        
        # Если у пользователя нет результатов, показываем сообщение
        if not assessment_results:
            flash('У вас пока нет результатов оценки. Пройдите тесты в разделе "Прохождение оценки"', 'info')
            return redirect(url_for('take_assessment'))
        
        # Получаем взаимооценки от других пользователей
        peer_evaluations = PeerEvaluation.query.filter_by(evaluated_id=current_user.id).all()
        debug_print(f"Найдено взаимооценок: {len(peer_evaluations)}")
        
        # Рассчитываем средний балл взаимооценки
        peer_score = 0
        if peer_evaluations:
            total_score = sum(eval.score for eval in peer_evaluations)
            peer_score = total_score / len(peer_evaluations) / 10  # Нормализуем до 0-1
            debug_print(f"Рассчитан peer_score: {peer_score}")
        
        # Обрабатываем данные для отображения
        assessment_data = []
        for block in blocks:
            try:
                debug_print(f"Обработка блока {block.id}: {block.name}")
                
                # Находим результат для этого блока
                result = next((r for r in assessment_results if r.block_id == block.id), None)
                
                if result:
                    # Получаем все вопросы блока
                    questions = AssessmentQuestion.query.filter_by(block_id=block.id).all()
                    debug_print(f"Найдено вопросов в блоке {block.id}: {len(questions)}")
                    
                    # Парсим ответы из JSON
                    answers = json.loads(result.answers) if result.answers else {}
                    debug_print(f"Ответы для блока {block.id}: {answers}")
                    
                    # Обрабатываем каждый вопрос
                    question_data = []
                    total_score = 0
                    max_possible_score = 0
                    
                    for question in questions:
                        try:
                            # Получаем ответ на вопрос
                            answer = answers.get(str(question.id))
                            
                            # Рассчитываем баллы в зависимости от типа вопроса
                            score = 0
                            max_score = question.points * (question.weight if question.weight else 1)
                            max_possible_score += max_score
                            
                            if question.type in ['single', 'multiple']:
                                if isinstance(answer, (int, list)):
                                    correct_answers = json.loads(question.correct_answer)
                                    if question.type == 'single':
                                        if answer == correct_answers[0]:
                                            score = max_score
                                    else:  # multiple
                                        correct_count = sum(1 for a in answer if a in correct_answers)
                                        total_correct = len(correct_answers)
                                        score = (correct_count / total_correct) * max_score
                            
                            elif question.type == 'code':
                                # Для кодовых вопросов проверяем оценки экспертов
                                expert_evaluations = ExpertCodeEvaluation.query.filter_by(
                                    assessment_result_id=result.id,
                                    question_id=question.id
                                ).all()
                                
                                if expert_evaluations:
                                    avg_score = sum(eval.score for eval in expert_evaluations) / len(expert_evaluations)
                                    score = (avg_score / 10) * max_score  # Нормализуем до максимального балла вопроса
                            
                            elif question.type == 'expert_evaluation':
                                # Для экспертной оценки используем средний балл
                                if isinstance(answer, list):
                                    score = (sum(answer) / len(answer)) * max_score
                            
                            total_score += score
                            
                            # Собираем данные о вопросе
                            question_info = {
                                'id': question.id,
                                'text': question.text,
                                'type': question.type,
                                'answer': answer,
                                'score': score,
                                'max_score': max_score,
                                'correct_answer': json.loads(question.correct_answer) if question.correct_answer else None,
                                'options': json.loads(question.options) if question.options else None,
                                'weight': question.weight,
                                'points': question.points
                            }
                            
                            question_data.append(question_info)
                            
                        except Exception as e:
                            debug_print(f"Ошибка при обработке вопроса {question.id}: {str(e)}")
                            continue
                    
                    # Добавляем информацию о блоке
                    block_info = {
                        'id': block.id,
                        'name': block.name,
                        'description': block.description,
                        'questions': question_data,
                        'total_score': total_score,
                        'max_possible_score': max_possible_score,
                        'score_percentage': (total_score / max_possible_score * 100) if max_possible_score > 0 else 0,
                        'weight': block.weight
                    }
                    
                    assessment_data.append(block_info)
                    debug_print(f"Данные для блока {block.id} добавлены в assessment_data")
                
            except Exception as e:
                debug_print(f"Ошибка при обработке блока {block.id}: {str(e)}")
                continue
        
        # Рассчитываем итоговую оценку
        final_score_data = calculate_final_score(current_user.id)
        
        debug_print(f"Подготовлено {len(assessment_data)} блоков для отображения")
        return render_template('assessment_results.html',
                             assessment_data=assessment_data,
                             peer_score=peer_score,
                             final_score=final_score_data)
                             
    except Exception as e:
        debug_print(f"Критическая ошибка при обработке результатов: {str(e)}")
        debug_print(f"Тип ошибки: {type(e)}")
        debug_print(f"Трейс ошибки:\n{traceback.format_exc()}")
        flash('Произошла ошибка при обработке результатов оценки', 'error')
        return redirect(url_for('index'))

@app.route('/peer_evaluation')
@login_required
def peer_evaluation():
    try:
        # Фильтруем только экспертов, исключая текущего пользователя и admin
        experts = User.query.filter(
            User.role == 'expert',
            User.id != current_user.id,
            User.username != 'admin'
        ).all()
        users_all = User.query.all()
        previous_evaluations = {}
        for eval in PeerEvaluation.query.filter_by(evaluator_id=current_user.id).all():
            previous_evaluations[eval.evaluated_id] = {'score': eval.score}
        return render_template('peer_evaluation.html',
                             experts=experts,
                             previous_evaluations=previous_evaluations,
                             users_all=users_all)
    except Exception as e:
        flash('Произошла ошибка при загрузке страницы взаимооценки', 'error')
        return redirect(url_for('index'))

@app.route('/submit_peer_evaluation', methods=['POST'])
@login_required
def submit_peer_evaluation():
    """Обработка результатов взаимооценки"""
    try:
        # Удаляем предыдущие оценки текущего пользователя
        PeerEvaluation.query.filter_by(evaluator_id=current_user.id).delete()
        
        # Сохраняем новые оценки
        for expert in User.query.filter(User.id != current_user.id).all():
            score = request.form.get(f'score_{expert.id}')
            if score is not None:
                try:
                    score = float(score)
                    if 0 <= score <= 10:
                        evaluation = PeerEvaluation(
                            evaluator_id=current_user.id,
                            evaluated_id=expert.id,
                            score=score
                        )
                        db.session.add(evaluation)
                except ValueError:
                    flash(f'Некорректная оценка для эксперта {expert.username}', 'error')
                    continue
        
        db.session.commit()
        flash('Оценки успешно сохранены', 'success')
        return redirect(url_for('assessment_results'))
    except Exception as e:
        db.session.rollback()
        print(f"Ошибка при сохранении оценок: {str(e)}")
        flash('Произошла ошибка при сохранении оценок', 'error')
        return redirect(url_for('peer_evaluation'))

@app.route('/work_group_evaluation')
@login_required
def work_group_evaluation():
    """Страница оценки рабочей группой"""
    users = User.query.filter(User.id != session['user_id']).all()
    return render_template('work_group_evaluation.html', users=users)

def calculate_kendall_coefficient(rankings):
    """
    Рассчитывает коэффициент конкордации Кенделла.
    
    Args:
        rankings (list): Список ранжирований, где каждое ранжирование - это список рангов
    
    Returns:
        float: Коэффициент конкордации Кенделла
    """
    try:
        if not rankings or len(rankings) < 2:
            return 0.0
        
        m = len(rankings)  # количество экспертов
        n = len(rankings[0])  # количество объектов
        
        # Рассчитываем средний ранг
        avg_rank = (n + 1) / 2
        
        # Рассчитываем сумму квадратов отклонений
        S = 0
        for i in range(n):
            rank_sum = sum(ranking[i] for ranking in rankings)
            S += (rank_sum - m * avg_rank) ** 2
        
        # Рассчитываем коэффициент конкордации
        W = 12 * S / (m ** 2 * (n ** 3 - n))
        
        return W
    
    except Exception as e:
        print(f"Ошибка при расчете коэффициента Кенделла: {str(e)}")
        return 0.0

def evaluate_work_group(user_id, criteria_scores):
    """
    Оценивает результаты работы в группе.
    
    Args:
        user_id (int): ID пользователя
        criteria_scores (dict): Словарь с оценками по критериям
    
    Returns:
        float: Итоговая оценка от 0 до 1
    """
    try:
        # Получаем все оценки рабочей группы для этого пользователя
        evaluations = WorkGroupEvaluation.query.filter_by(
            evaluated_id=user_id
        ).all()
        
        if not evaluations:
            return 0.0
        
        # Собираем ранжирования по каждому критерию
        rankings = []
        for criterion in ['competence', 'conformity', 'experience', 'interest', 'business', 'objectivity']:
            criterion_ranks = []
            for eval in evaluations:
                try:
                    scores = json.loads(eval.criteria_scores)
                    criterion_ranks.append(scores.get(criterion, 0))
                except (json.JSONDecodeError, TypeError):
                    continue
            
            if criterion_ranks:
                rankings.append(criterion_ranks)
        
        # Рассчитываем коэффициент конкордации
        W = calculate_kendall_coefficient(rankings)
        
        # Если согласованность экспертов достаточная (W >= 0.5)
        if W >= 0.5:
            # Рассчитываем взвешенную оценку
            weighted_score = (
                criteria_scores.get('competence', 0) * 0.23 +
                criteria_scores.get('conformity', 0) * 0.2 +
                criteria_scores.get('experience', 0) * 0.15 +
                criteria_scores.get('interest', 0) * 0.12 +
                criteria_scores.get('business', 0) * 0.13 +
                criteria_scores.get('objectivity', 0) * 0.17
            )
            
            # Нормализуем оценку
            return weighted_score / 10  # Предполагаем, что максимальная оценка по критерию - 10
        
        return 0.0
    
    except Exception as e:
        print(f"Ошибка при оценке рабочей группы: {str(e)}")
        return 0.0

@app.route('/submit_work_group_evaluation', methods=['POST'])
@login_required
def submit_work_group_evaluation():
    """Обработка результатов оценки рабочей группой"""
    try:
        for user_id in request.form:
            if user_id.startswith('criteria_'):
                evaluated_id = int(user_id.split('_')[1])
                
                # Собираем оценки по всем критериям
                criteria_scores = {
                    'competence': float(request.form.get(f'competence_{evaluated_id}', 0)),
                    'conformity': float(request.form.get(f'conformity_{evaluated_id}', 0)),
                    'experience': float(request.form.get(f'experience_{evaluated_id}', 0)),
                    'interest': float(request.form.get(f'interest_{evaluated_id}', 0)),
                    'business': float(request.form.get(f'business_{evaluated_id}', 0)),
                    'objectivity': float(request.form.get(f'objectivity_{evaluated_id}', 0))
                }
                
                # Рассчитываем итоговую оценку
                final_score = evaluate_work_group(evaluated_id, criteria_scores)
                
                # Сохраняем оценку
                evaluation = WorkGroupEvaluation(
                    evaluator_id=session['user_id'],
                    evaluated_id=evaluated_id,
                    criteria_scores=json.dumps(criteria_scores)
                )
                db.session.add(evaluation)
        
        db.session.commit()
        flash('Ваши оценки успешно сохранены', 'success')
        return redirect(url_for('index'))
    
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при сохранении оценок: {str(e)}', 'error')
        return redirect(url_for('work_group_evaluation'))

def init_assessment_blocks():
    """Инициализация блоков оценки"""
    try:
        debug_print("Начинаем инициализацию блоков оценки...")
        
        # Check if blocks already exist
        if AssessmentBlock.query.first() is not None:
            debug_print("Блоки оценки уже существуют")
            return True
        
        # Create assessment blocks
        blocks = [
            {
                'name': 'Компетентность в сфере фронтенд-разработки и основных языках',
                'description': 'Оценка компетентности в сфере фронтенд-разработки и основных языков',
                'max_score': 67,
                'weight': 0.17
            },
            {
                'name': 'Квалиметрическая компетентность',
                'description': 'Оценка квалиметрической компетентности',
                'max_score': 23,
                'weight': 0.155
            },
            {
                'name': 'Креативность',
                'description': 'Оценка креативного мышления',
                'max_score': 100,
                'weight': 0.125
            },
            {
                'name': 'Взаимооценка',
                'description': 'Оценка компетенций коллегами',
                'max_score': 100,
                'weight': 0.09
            },
            {
                'name': 'Воспроизводимость',
                'description': 'Оценка воспроизводимости результатов',
                'max_score': 100,
                'weight': 0.145
            },
            {
                'name': 'Конформизм',
                'description': 'Оценка уровня конформизма',
                'max_score': 100,
                'weight': 0.11
            },
            {
                'name': 'Самооценка',
                'description': 'Оценка собственных компетенций',
                'max_score': 12.5,
                'weight': 0.1
            },
            {
                'name': 'Оценка рабочей группой',
                'description': 'Блок для оценки экспертов рабочей группой, включающий опыт, заинтересованность и деловитость',
                'max_score': 100,
                'weight': 0.105
            }
        ]
        
        for block_data in blocks:
            try:
                block = AssessmentBlock(**block_data)
                db.session.add(block)
                debug_print(f"Добавлен блок: {block.name}")
            except Exception as e:
                debug_print(f"Ошибка при добавлении блока {block_data['name']}: {str(e)}")
                db.session.rollback()
                return False
        
        try:
            db.session.commit()
            debug_print("Блоки оценки созданы успешно")
            return True
        except Exception as e:
            debug_print(f"Ошибка при сохранении блоков: {str(e)}")
            db.session.rollback()
            return False
            
    except Exception as e:
        debug_print(f"Критическая ошибка при создании блоков оценки: {str(e)}")
        return False

def init_assessment_questions():
    """Инициализация вопросов оценки"""
    try:
        debug_print("Начинаем инициализацию вопросов оценки...")
        
        # Get all blocks
        blocks = AssessmentBlock.query.all()
        if not blocks:
            debug_print("Ошибка: блоки оценки не найдены")
            return False
        
        debug_print(f"Найдено блоков: {len(blocks)}")
        
        # Track if we've added any questions
        questions_added = False
        
        for block in blocks:
            debug_print(f"Обработка блока {block.id}: {block.name}")
            
            # Check if block already has questions
            existing_questions = AssessmentQuestion.query.filter_by(block_id=block.id).first()
            if existing_questions:
                debug_print(f"Блок {block.name} уже имеет вопросы")
                questions_added = True
                continue
            
            block_file = os.path.join('blocks', f'block{block.id}.json')
            debug_print(f"Пытаемся загрузить файл: {block_file}")
            
            if os.path.exists(block_file):
                debug_print(f"Файл {block_file} найден")
                try:
                    with open(block_file, 'r', encoding='utf-8') as f:
                        block_data = json.load(f)
                        questions = block_data.get('questions', [])
                        debug_print(f"Загружено вопросов из файла: {len(questions)}")
                    
                    for question_data in questions:
                        try:
                            question = AssessmentQuestion(
                                block_id=block.id,
                                type=question_data['type'],
                                text=question_data['text'],
                                points=question_data.get('points', 1)
                            )
                            
                            if 'options' in question_data:
                                question.options = json.dumps(question_data['options'])
                            if 'correct_answer' in question_data:
                                question.correct_answer = json.dumps(question_data['correct_answer'])
                            if 'code_template' in question_data:
                                question.code_template = question_data['code_template']
                            if 'test_cases' in question_data:
                                question.test_cases = json.dumps(question_data['test_cases'])
                            if 'option_scores' in question_data:
                                question.option_scores = json.dumps(question_data['option_scores'])
                            if 'weight' in question_data:
                                question.weight = question_data['weight']
                            if 'description' in question_data:
                                question.description = question_data['description']
                            if 'criteria' in question_data:
                                question.criteria = json.dumps(question_data['criteria'])
                            if 'max_score' in question_data:
                                question.max_score = question_data['max_score']
                            
                            db.session.add(question)
                            questions_added = True
                            debug_print(f"Добавлен вопрос: {question.text[:50]}...")
                        except Exception as e:
                            debug_print(f"Ошибка при создании вопроса: {str(e)}")
                            continue
                except Exception as e:
                    debug_print(f"Ошибка при чтении файла {block_file}: {str(e)}")
                    continue
            else:
                debug_print(f"Файл {block_file} не найден!")
        
        if not questions_added:
            debug_print("Не было добавлено ни одного вопроса!")
            return False
        
        try:
            db.session.commit()
            debug_print("Вопросы успешно добавлены в базу данных")
            return True
        except Exception as e:
            debug_print(f"Ошибка при сохранении вопросов: {str(e)}")
            db.session.rollback()
            return False
            
    except Exception as e:
        debug_print(f"Критическая ошибка при инициализации вопросов: {str(e)}")
        db.session.rollback()
        return False

    # Проверяем, существует ли блок 'Самооценка'
    self_assessment_block = AssessmentBlock.query.filter_by(name='Самооценка').first()
    if not self_assessment_block:
        self_assessment_block = AssessmentBlock(name='Самооценка', weight=0.1, max_score=12.5)
        db.session.add(self_assessment_block)
        db.session.commit()
        debug_print("Создан блок 'Самооценка'")

    # Загружаем вопросы для блока 'Самооценка' из файла
    block4_file = 'blocks/block4.json'
    if os.path.exists(block4_file):
        with open(block4_file, 'r', encoding='utf-8') as f:
            block4_data = json.load(f)
            questions = block4_data.get('questions', [])
            for question_data in questions:
                question = AssessmentQuestion(
                    block_id=self_assessment_block.id,
                    type=question_data['type'],
                    text=question_data['text'],
                    weight=question_data['weight'],
                    options=json.dumps(question_data['options'])
                )
                db.session.add(question)
        db.session.commit()
        debug_print("Вопросы блока 'Самооценка' добавлены в базу данных")
    else:
        debug_print(f"Файл {block4_file} не найден!")

@app.route('/assessment_system')
@login_required
def assessment_system():    
    try:
        # Define excluded blocks
        excluded_blocks = [
            'Конформизм',
            'Воспроизводимость',
            'Оценка рабочей группой'
        ]
        
        # Get all blocks except the excluded ones
        blocks = AssessmentBlock.query.filter(
            ~AssessmentBlock.name.in_(excluded_blocks)
        ).all()
        
        # For each block get current user's results and add useful information
        for block in blocks:
            result = AssessmentResult.query.filter_by(
                user_id=session['user_id'],
                block_id=block.id
            ).order_by(AssessmentResult.date.desc()).first()
            
            # Get average score for this block from all users
            all_results = AssessmentResult.query.filter_by(block_id=block.id).all()
            avg_score = sum(r.score for r in all_results) / len(all_results) if all_results else 0
            
            # Get number of users who completed this block
            block.avg_score = result.score if result else None
        
        # Получаем количество экспертов
        expert_count = User.query.filter_by(role='expert').count()
        
        # Если текущий пользователь эксперт, уменьшаем количество на 1
        if session.get('role') == 'expert':
            expert_count -= 1
        
        return render_template('assessment_system.html', blocks=blocks, expert_count=expert_count)
    except Exception as e:
        debug_print(f"Ошибка при загрузке блока assessment_system: {str(e)}")
        debug_print(f"Трейс ошибки:\n{traceback.format_exc()}")
        flash('Произошла ошибка при загрузке блока', 'error')
        return redirect(url_for('index'))

@app.route('/assessment/stats')
@login_required
def assessment_stats():
    try:
        debug_print("Начало функции assessment_stats")
        
        # Получаем все оценки, исключая блоки Воспроизводимость и Конформизм
        results = AssessmentResult.query\
            .join(AssessmentBlock)\
            .filter(~AssessmentBlock.name.in_(['Воспроизводимость', 'Конформизм']))\
            .all()
        debug_print(f"Найдено результатов оценки: {len(results)}")

        # Получаем все блоки, исключая Воспроизводимость и Конформизм
        blocks = AssessmentBlock.query\
            .filter(~AssessmentBlock.name.in_(['Воспроизводимость', 'Конформизм']))\
            .all()
        debug_print(f"Найдено блоков: {len(blocks)}")
        for block in blocks:
            debug_print(f"Блок: {block.name}, ID: {block.id}")
        
        if not blocks:
            debug_print("Нет доступных блоков оценки")
            flash('Нет доступных блоков оценки', 'warning')
            return redirect(url_for('index'))
        
        # Подготавливаем статистику по блокам
        block_stats = {}
        for block in blocks:
            block_results = [r for r in results if r.block_id == block.id]
            debug_print(f"Для блока {block.name} найдено результатов: {len(block_results)}")
            
            if block_results:
                scores = [r.score for r in block_results]
                block_stats[block.id] = {
                    'name': block.name,
                    'avg_score': sum(scores) / len(scores) if scores else 0,
                    'max_score': max(scores) if scores else 0,
                    'min_score': min(scores) if scores else 0,
                    'count': len(scores)
                }
                debug_print(f"Статистика для блока {block.name}: {block_stats[block.id]}")
            else:
                block_stats[block.id] = {
                    'name': block.name,
                    'avg_score': 0,
                    'max_score': 0,
                    'min_score': 0,
                    'count': 0
                }
                debug_print(f"Нет результатов для блока {block.name}")
        
        # Подготавливаем данные для графиков
        score_ranges = ['0-20', '21-40', '41-60', '61-80', '81-100']
        score_counts = [0] * len(score_ranges)
        
        for result in results:
            score_percentage = (result.score / result.block.max_score) * 100
            debug_print(f"Обработка результата: score={result.score}, max_score={result.block.max_score}, percentage={score_percentage}")
            if score_percentage <= 20:
                score_counts[0] += 1
            elif score_percentage <= 40:
                score_counts[1] += 1
            elif score_percentage <= 60:
                score_counts[2] += 1
            elif score_percentage <= 80:
                score_counts[3] += 1
            else:
                score_counts[4] += 1
        
        debug_print(f"Распределение оценок по диапазонам: {dict(zip(score_ranges, score_counts))}")
        
        # Подготавливаем данные для графика средних оценок по блокам
        block_names = [block.name for block in blocks]
        avg_scores = []
        for block in blocks:
            block_results = [r for r in results if r.block_id == block.id]
            if block_results:
                avg_score = sum(r.score for r in block_results) / len(block_results)
                avg_scores.append(avg_score)
            else:
                avg_scores.append(0)
            debug_print(f"Средняя оценка для блока {block.name}: {avg_scores[-1]}")
        
        debug_print("Подготовка к рендерингу шаблона")
        return render_template('assessment_stats.html',
                             blocks=blocks,
                             block_stats=block_stats,
                             score_ranges=score_ranges,
                             score_counts=score_counts,
                             block_names=block_names,
                             avg_scores=avg_scores)
    except Exception as e:
        debug_print(f"Ошибка при загрузке статистики: {str(e)}")
        debug_print(f"Тип ошибки: {type(e)}")
        debug_print(f"Трейс ошибки:\n{traceback.format_exc()}")
        flash('Произошла ошибка при загрузке статистики', 'error')
        return redirect(url_for('index'))

def init_db():
    """Инициализация базы данных"""
    try:
        debug_print("Начинаем инициализацию базы данных...")
        
        with app.app_context():
            debug_print("Создаем таблицы...")
            db.create_all()
            debug_print("Таблицы созданы успешно")
            
            debug_print("Проверяем существование администратора...")
            admin_exists = User.query.filter_by(role='admin').first() is not None
            
            if not admin_exists:
                debug_print("Создаем пользователя-администратора...")
                admin_user = User(username='admin', role='admin')
                admin_user.set_password('admin123')
                db.session.add(admin_user)
                try:
                    db.session.commit()
                    debug_print("Создан пользователь-администратор: логин 'admin', пароль 'admin123'")
                except Exception as e:
                    db.session.rollback()
                    debug_print(f"Ошибка при создании администратора: {str(e)}")
                    return False
            
            if not create_expert_users():
                debug_print("Ошибка при создании экспертов")
                return False
                
            if not create_working_group_users():
                debug_print("Ошибка при создании пользователей рабочей группы")
                return False
            
            debug_print("Инициализируем блоки оценки...")
            if not init_assessment_blocks():
                debug_print("Ошибка при инициализации блоков оценки")
                return False
            
            debug_print("Инициализируем вопросы оценки...")
            if not init_assessment_questions():
                debug_print("Ошибка при инициализации вопросов оценки")
                return False
            
            debug_print("Инициализация базы данных завершена успешно")
            return True
            
    except Exception as e:
        debug_print(f"Критическая ошибка при инициализации базы данных: {str(e)}")
        debug_print(f"Тип ошибки: {type(e)}")
        debug_print(f"Трейс ошибки:\n{traceback.format_exc()}")
        return False

def create_expert_users():
    """Создание пользователей-экспертов"""
    try:
        expert_names = ['Иванов', 'Петров', 'Сидоров', 'Смирнов', 'Кузнецов']
        for name in expert_names:
            if not User.query.filter_by(username=name).first():
                user = User(username=name, role='expert')
                user.set_password(name)
                db.session.add(user)
        db.session.commit()
        debug_print('Эксперты успешно созданы!')
        return True
    except Exception as e:
        db.session.rollback()
        debug_print(f"Ошибка при создании экспертов: {str(e)}")
        return False

def create_working_group_users():
    """Создание пользователей рабочей группы"""
    try:
        working_group_users = [
            {'username': 'Михайлов', 'password': 'group123'},
            {'username': 'Андреев', 'password': 'group123'},
            {'username': 'Николаев', 'password': 'group123'}
        ]
        
        for user_data in working_group_users:
            if not User.query.filter_by(username=user_data['username']).first():
                user = User(username=user_data['username'], role='working_group')
                user.set_password(user_data['password'])
                db.session.add(user)
                
                # Создаем тестовые результаты оценки для каждого пользователя
                blocks = AssessmentBlock.query.all()
                for block in blocks:
                    if block.name != 'Оценка рабочей группой':  # Пропускаем блок рабочей группы
                        # Генерируем случайную оценку от 70 до 95
                        score = random.uniform(70, 95)
                        result = AssessmentResult(
                            user_id=user.id,
                            block_id=block.id,
                            score=score,
                            answers=json.dumps({'auto_generated': True})
                        )
                        db.session.add(result)
        
        db.session.commit()
        debug_print('Пользователи рабочей группы успешно созданы!')
        return True
    except Exception as e:
        db.session.rollback()
        debug_print(f"Ошибка при создании пользователей рабочей группы: {str(e)}")
        return False

def load_blocks():
    blocks = []
    blocks_dir = os.path.join(os.path.dirname(__file__), 'blocks')
    for filename in os.listdir(blocks_dir):
        if filename.endswith('.json'):
            with open(os.path.join(blocks_dir, filename), 'r', encoding='utf-8') as f:
                block_data = json.load(f)
                blocks.append(block_data)
    return blocks

@app.route('/blocks')
@login_required
def blocks():
    blocks = load_blocks()
    return render_template('blocks.html', blocks=blocks)

@app.route('/working_group_experience')
@login_required
def working_group_experience():
    block = None
    with open('blocks/block8.json', 'r', encoding='utf-8') as f:
        block_data = json.load(f)
        for question in block_data['questions']:
            if question['text'] == 'Опыт':
                block = question
                break
    
    if not block:
        flash('Блок оценки опыта не найден', 'error')
        return redirect(url_for('assessment_system'))
    
    return render_template('working_group_assessment.html', 
                         title='Оценка опыта',
                         block=block,
                         assessment_type='experience')

@app.route('/working_group_interest')
@login_required
def working_group_interest():
    block = None
    with open('blocks/block8.json', 'r', encoding='utf-8') as f:
        block_data = json.load(f)
        for question in block_data['questions']:
            if question['text'] == 'Заинтересованность в работе экспертной комиссии':
                block = question
                break
    
    if not block:
        flash('Блок оценки заинтересованности не найден', 'error')
        return redirect(url_for('assessment_system'))
    
    return render_template('working_group_assessment.html', 
                         title='Оценка заинтересованности',
                         block=block,
                         assessment_type='interest')

@app.route('/working_group_evaluation')
@role_required(['working_group'])
def working_group_evaluation():
    block = None
    with open('blocks/block8.json', 'r', encoding='utf-8') as f:
        block_data = json.load(f)
        for question in block_data['questions']:
            if question['text'] == 'Деловитость эксперта':
                block = question
                break
    
    if not block:
        flash('Блок оценки деловитости не найден', 'error')
        return redirect(url_for('assessment_system'))
    
    # Получаем список экспертов для оценки
    experts = User.query.filter_by(role='expert').all()
    
    return render_template('working_group_evaluation.html', 
                         title='Оценка деловитости',
                         block=block,
                         experts=experts)

@app.route('/submit_working_group_assessment', methods=['POST'])
@login_required
def submit_working_group_assessment():
    assessment_type = request.form.get('assessment_type')
    scores = {}
    
    # Получаем данные из формы
    for key, value in request.form.items():
        if key.startswith('criteria_'):
            scores[key.replace('criteria_', '')] = float(value)
    
    # Загружаем блок для получения весов
    with open('blocks/block8.json', 'r', encoding='utf-8') as f:
        block_data = json.load(f)
        for question in block_data['questions']:
            if (assessment_type == 'experience' and question['text'] == 'Опыт') or \
               (assessment_type == 'interest' and question['text'] == 'Заинтересованность в работе экспертной комиссии'):
                weight = question['weight']
                max_score = question['max_score']
                break
    
    # Вычисляем общий балл
    total_score = sum(scores.values())
    normalized_score = (total_score / max_score) * 100
    
    # Сохраняем результат
    result = AssessmentResult(
        user_id=session['user_id'],
        block_id=8,  # ID блока рабочей группы
        score=normalized_score * weight
    )
    db.session.add(result)
    db.session.commit()
    
    flash(f'Оценка успешно сохранена. Ваш балл: {normalized_score:.2f}', 'success')
    return redirect(url_for('assessment_system'))

@app.route('/submit_working_group_evaluation', methods=['POST'])
@role_required(['working_group'])
def submit_working_group_evaluation():
    expert_id = request.form.get('expert_id')
    if not expert_id:
        flash('Не указан эксперт для оценки', 'error')
        return redirect(url_for('working_group_evaluation'))
    
    scores = {}
    # Получаем данные из формы
    for key, value in request.form.items():
        if key.startswith('criteria_'):
            scores[key.replace('criteria_', '')] = float(value)
    
    # Загружаем блок для получения весов
    with open('blocks/block8.json', 'r', encoding='utf-8') as f:
        block_data = json.load(f)
        for question in block_data['questions']:
            if question['text'] == 'Деловитость эксперта':
                weight = question['weight']
                max_score = question['max_score']
                break
    
    # Вычисляем общий балл
    total_score = sum(scores.values())
    normalized_score = (total_score / max_score) * 100
    
    # Сохраняем оценку
    evaluation = WorkGroupEvaluation(
        evaluator_id=session['user_id'],
        evaluated_id=expert_id,
        criteria_scores=json.dumps(scores)
    )
    db.session.add(evaluation)
    
    # Проверяем согласованность оценок с помощью коэффициента конкордации Кенделла
    all_evaluations = WorkGroupEvaluation.query.filter_by(evaluated_id=expert_id).all()
    if len(all_evaluations) >= 3:  # Если есть хотя бы 3 оценки
        rankings = []
        for eval in all_evaluations:
            eval_scores = json.loads(eval.criteria_scores)
            rankings.append(list(eval_scores.values()))
        
        kendall_w = calculate_kendall_coefficient(rankings)
        if kendall_w < 0.7:  # Если согласованность низкая
            flash('Внимание: низкая согласованность оценок между экспертами (W < 0.7)', 'warning')
    
    db.session.commit()
    
    flash(f'Оценка эксперта успешно сохранена. Балл деловитости: {normalized_score:.2f}', 'success')
    return redirect(url_for('working_group_evaluation'))

if __name__ == '__main__':
    debug_print("Запуск приложения...")
    try:
        debug_print("Начинаем инициализацию базы данных...")
        if not init_db():
            debug_print("Ошибка при инициализации базы данных. Приложение будет остановлено.")
            exit(1)
        
        debug_print("База данных инициализирована успешно")
        
        # Load test data if available
        try:
            test_data_script = os.path.join(os.path.dirname(__file__), 'test_data_filler', 'fill_test_data.py')
            if os.path.exists(test_data_script):
                debug_print("Запускаем скрипт заполнения тестовыми данными...")
                subprocess.run([sys.executable, test_data_script], check=True)
                debug_print("Тестовые данные успешно добавлены!")
            else:
                debug_print("Скрипт заполнения тестовыми данными не найден.")
        except Exception as e:
            debug_print(f"Ошибка при запуске скрипта заполнения тестовыми данными: {str(e)}")
        
        app.run(debug=True)
    except Exception as e:
        debug_print(f"Критическая ошибка при запуске приложения: {str(e)}")
        debug_print(f"Тип ошибки: {type(e)}")
        debug_print(f"Трейс ошибки:\n{traceback.format_exc()}")
        exit(1)
