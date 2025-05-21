import json
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Создаем экземпляр SQLAlchemy
db = SQLAlchemy()

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
        roles = {
            'user': 'Пользователь',
            'expert': 'Эксперт',
            'admin': 'Администратор',
            'working_group': 'Рабочая группа'
        }
        return roles.get(self.role, 'Пользователь')

class AssessmentBlock(db.Model):
    __tablename__ = 'assessment_block'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    weight = db.Column(db.Float, default=1.0)
    max_score = db.Column(db.Float, default=10.0)
    questions = db.relationship('AssessmentQuestion', back_populates='block', lazy=True)

class AssessmentQuestion(db.Model):
    __tablename__ = 'assessment_question'
    id = db.Column(db.Integer, primary_key=True)
    block_id = db.Column(db.Integer, db.ForeignKey('assessment_block.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), nullable=False)
    options = db.Column(db.Text)
    correct_answer = db.Column(db.Text)
    correct_answer_description = db.Column(db.Text)
    points = db.Column(db.Integer, default=1)
    code_template = db.Column(db.Text)
    test_cases = db.Column(db.Text)
    example_solutions = db.Column(db.Text)
    block = db.relationship('AssessmentBlock', foreign_keys=[block_id])
    option_scores = db.Column(db.Text)
    description = db.Column(db.Text)
    criteria = db.Column(db.Text)
    max_score = db.Column(db.Float)
    weight = db.Column(db.Float)

    @property
    def options_list(self):
        """Возвращает список опций из JSON строки"""
        if not self.options:
            return []
        try:
            return json.loads(self.options)
        except json.JSONDecodeError:
            return []

    @property
    def correct_answers_list(self):
        """Возвращает список правильных ответов из JSON строки"""
        if not self.correct_answer:
            return []
        try:
            return json.loads(self.correct_answer)
        except json.JSONDecodeError:
            # В случае, если correct_answer хранится как строка
            return [self.correct_answer]

class AssessmentResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    block_id = db.Column(db.Integer, db.ForeignKey('assessment_block.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    answers = db.Column(db.String(5000))
    
    block = db.relationship('AssessmentBlock', backref='results')
    user = db.relationship('User', backref='assessment_results')

    def get_answers_dict(self):
        """Получает словарь ответов из JSON строки"""
        if not self.answers:
            return {}
        try:
            return json.loads(self.answers)
        except json.JSONDecodeError:
            return {}

    def set_answers_dict(self, answers_dict):
        """Устанавливает ответы из словаря"""
        self.answers = json.dumps(answers_dict)

class PeerEvaluation(db.Model):
    """Модель для хранения взаимооценок экспертов"""
    __tablename__ = 'peer_evaluations'
    
    id = db.Column(db.Integer, primary_key=True)
    evaluator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    evaluated_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    criteria_scores = db.Column(db.String(1000), nullable=False)  # JSON string with scores for each criterion
    comments = db.Column(db.Text)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Связи с пользователями
    evaluator = db.relationship('User', foreign_keys=[evaluator_id], backref='given_evaluations')
    evaluated = db.relationship('User', foreign_keys=[evaluated_id], backref='received_evaluations')
    
    def __repr__(self):
        return f'<PeerEvaluation {self.evaluator.username} -> {self.evaluated.username}: {self.score}>'
    
    @property
    def criteria_scores_dict(self):
        """Возвращает оценки по критериям как словарь"""
        try:
            return json.loads(self.criteria_scores)
        except (json.JSONDecodeError, TypeError):
            return {}
    
    @criteria_scores_dict.setter
    def criteria_scores_dict(self, value):
        """Устанавливает оценки по критериям из словаря"""
        self.criteria_scores = json.dumps(value)
    
    @property
    def average_score(self):
        """Рассчитывает средний балл по всем критериям"""
        scores = self.criteria_scores_dict.values()
        return sum(scores) / len(scores) if scores else 0 

class WorkGroupEvaluation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evaluator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    evaluated_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    criteria_scores = db.Column(db.String(1000))
    date = db.Column(db.DateTime, default=datetime.utcnow)

class ExpertCodeEvaluation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assessment_result_id = db.Column(db.Integer, db.ForeignKey('assessment_result.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('assessment_question.id'), nullable=False)
    expert_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    comments = db.Column(db.String(1000))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    
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
    
    question = db.relationship('AssessmentQuestion')
    expert = db.relationship('User') 