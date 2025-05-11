import json
from datetime import datetime

class PeerEvaluation(db.Model):
    """Модель для хранения взаимооценок экспертов"""
    __tablename__ = 'peer_evaluations'
    
    id = db.Column(db.Integer, primary_key=True)
    evaluator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    evaluated_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
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