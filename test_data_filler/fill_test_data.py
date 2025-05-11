import os
import random
import sys
import json
from datetime import datetime
import importlib.util

# Динамически импортируем основной модуль приложения (1.py)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
main_path = os.path.join(BASE_DIR, '1.py')
spec = importlib.util.spec_from_file_location('main_app', main_path)
main_app = importlib.util.module_from_spec(spec)
sys.modules['main_app'] = main_app
spec.loader.exec_module(main_app)

db = main_app.db
User = main_app.User
AssessmentBlock = main_app.AssessmentBlock
AssessmentQuestion = main_app.AssessmentQuestion
AssessmentResult = main_app.AssessmentResult
PeerEvaluation = main_app.PeerEvaluation
ExpertCodeEvaluation = main_app.ExpertCodeEvaluation
app = main_app.app

EXPERT_NAMES = ['Иванов', 'Петров', 'Сидоров', 'Смирнов', 'Кузнецов']

# Примеры кода для code-вопросов
EXAMPLE_CODES = [
    'function test() { return 42; }',
    'let a = 1; let b = 2; return a + b;',
    'console.log("Hello, world!");',
    'function sum(a, b) { return a + b; }',
    'for (let i = 0; i < 10; i++) { console.log(i); }'
]

def random_answer(question, expert_idx=0):
    if question.type == 'single':
        options = json.loads(question.options)
        # Разные эксперты выбирают разные варианты
        return str((expert_idx + 1) % len(options))
    elif question.type == 'multiple':
        options = json.loads(question.options)
        indices = list(range(len(options)))
        random.seed(expert_idx)
        random.shuffle(indices)
        selected = indices[:(expert_idx % len(options)) + 1]
        return [str(i) for i in selected]
    elif question.type == 'open':
        return f'Ответ эксперта {expert_idx+1}'
    elif question.type == 'code':
        # Разные коды для разных экспертов
        return EXAMPLE_CODES[expert_idx % len(EXAMPLE_CODES)] + f' // expert {expert_idx+1}'
    elif question.type == 'matching':
        options = json.loads(question.options)
        # Сдвиг индексов для каждого эксперта
        return [str((i + expert_idx) % len(options)) for i in range(len(options))]
    else:
        return ''

def fill_test_data():
    with app.app_context():
        # Создаём экспертов, если их нет
        experts = []
        for name in EXPERT_NAMES:
            user = User.query.filter_by(username=name).first()
            if not user:
                user = User(username=name, role='expert')
                user.set_password(name)
                db.session.add(user)
                db.session.commit()
            experts.append(user)
        print(f'Эксперты: {[e.username for e in experts]}')

        blocks = AssessmentBlock.query.all()
        for expert_idx, expert in enumerate(experts):
            for block in blocks:
                # Пропускаем, если уже есть результат
                existing = AssessmentResult.query.filter_by(user_id=expert.id, block_id=block.id).first()
                if existing:
                    continue
                # --- Взаимооценка ---
                if block.id == 5 or 'Взаимооценка' in block.name:
                    answers = {}
                    total_score = 0
                    for other in experts:
                        if other.id == expert.id:
                            continue
                        # Оценка зависит от индекса эксперта и оцениваемого
                        score = 5 + ((expert_idx + other.id) % 6)  # 5..10
                        answers[str(other.id)] = str(score)
                        total_score += score
                        # Создаём PeerEvaluation
                        existing_peer = PeerEvaluation.query.filter_by(evaluator_id=expert.id, evaluated_id=other.id).first()
                        if not existing_peer:
                            evaluation = PeerEvaluation(
                                evaluator_id=expert.id,
                                evaluated_id=other.id,
                                score=score
                            )
                            db.session.add(evaluation)
                    result = AssessmentResult(
                        user_id=expert.id,
                        block_id=block.id,
                        score=total_score,
                        answers=json.dumps(answers, ensure_ascii=False)
                    )
                    db.session.add(result)
                    db.session.commit()
                    continue
                # --- Остальные блоки ---
                questions = AssessmentQuestion.query.filter_by(block_id=block.id).all()
                answers = {}
                total_score = 0
                for q in questions:
                    ans = random_answer(q, expert_idx)
                    answers[str(q.id)] = ans if isinstance(ans, str) else json.dumps(ans)
                    # Простейшее начисление баллов (можно усложнить)
                    total_score += 1
                result = AssessmentResult(
                    user_id=expert.id,
                    block_id=block.id,
                    score=total_score,
                    answers=json.dumps(answers, ensure_ascii=False)
                )
                db.session.add(result)
                db.session.commit()

        # Экспертные оценки кода: каждый эксперт оценивает коды других
        code_questions = AssessmentQuestion.query.filter_by(type='code').all()
        for question in code_questions:
            results = AssessmentResult.query.filter(AssessmentResult.answers.like(f'%{question.id}%')).all()
            for result in results:
                if not result.answers:
                    continue
                answers = json.loads(result.answers)
                user_code = answers.get(str(question.id), '')
                if not user_code:
                    continue
                for expert in experts:
                    if expert.id == result.user_id:
                        continue
                    existing = ExpertCodeEvaluation.query.filter_by(
                        assessment_result_id=result.id,
                        question_id=question.id,
                        expert_id=expert.id
                    ).first()
                    if not existing:
                        evaluation = ExpertCodeEvaluation(
                            assessment_result_id=result.id,
                            question_id=question.id,
                            expert_id=expert.id,
                            score=5 + ((expert.id + result.id) % 6),
                            comments=f'Эксперт {expert.username} оценил код пользователя {result.user_id}',
                            date=datetime.utcnow()
                        )
                        db.session.add(evaluation)
        db.session.commit()
        print('Тестовые данные успешно добавлены!')

if __name__ == '__main__':
    fill_test_data() 