import os
import random
import sys
import json
from datetime import datetime
import importlib.util
import string

# Add the parent directory to sys.path so Python can find the modules
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# Import directly after adding to path
from models import db, User, AssessmentBlock, AssessmentQuestion, AssessmentResult, PeerEvaluation, ExpertCodeEvaluation

# Динамически импортируем основной модуль приложения (1.py)
main_path = os.path.join(BASE_DIR, '1.py')
spec = importlib.util.spec_from_file_location('main_app', main_path)
main_app = importlib.util.module_from_spec(spec)
sys.modules['main_app'] = main_app
spec.loader.exec_module(main_app)

# Use the main_app's app instance
app = main_app.app

# Расширенный список имен для генерации пользователей
FIRST_NAMES = ['Иван', 'Петр', 'Сергей', 'Александр', 'Михаил', 'Дмитрий', 'Андрей', 'Николай', 'Владимир', 'Игорь']
LAST_NAMES = ['Иванов', 'Петров', 'Сидоров', 'Смирнов', 'Кузнецов', 'Попов', 'Соколов', 'Лебедев', 'Козлов', 'Новиков']

# Примеры кода для code-вопросов с разной сложностью
EXAMPLE_CODES = [
    # Простые примеры
    'function sum(a, b) { return a + b; }',
    'console.log("Hello, world!");',
    'let x = 10; console.log(x);',
    # Средние примеры
    '''function factorial(n) {
    if (n <= 1) return 1;
    return n * factorial(n-1);
}''',
    '''const arr = [1, 2, 3, 4, 5];
const doubled = arr.map(x => x * 2);''',
    # Сложные примеры
    '''class Calculator {
    constructor() {
        this.value = 0;
    }
    add(x) {
        this.value += x;
        return this;
    }
    subtract(x) {
        this.value -= x;
        return this;
    }
    getResult() {
        return this.value;
    }
}'''
]

def generate_random_user():
    """Генерация случайного пользователя"""
    first_name = random.choice(FIRST_NAMES)
    last_name = random.choice(LAST_NAMES)
    username = f"{first_name}_{last_name}_{random.randint(1, 999)}"
    role = random.choice(['user', 'expert', 'working_group'])
    return username, role

def random_answer(question, user_id):
    """Генерация случайного ответа с учетом ID пользователя"""
    random.seed(user_id + hash(question.text) % 1000)  # Уникальный seed для каждой комбинации пользователь-вопрос
    
    if question.type == 'single':
        options = json.loads(question.options)
        return str(random.randint(0, len(options) - 1))
    
    elif question.type == 'multiple':
        options = json.loads(question.options)
        num_selections = random.randint(1, len(options))
        selected = random.sample(range(len(options)), num_selections)
        return [str(i) for i in selected]
    
    elif question.type == 'open':
        words = ['отличный', 'хороший', 'средний', 'удовлетворительный', 'неудовлетворительный']
        adjectives = ['очень', 'достаточно', 'относительно', 'не очень', 'крайне']
        return f"{random.choice(adjectives)} {random.choice(words)} ответ от пользователя {user_id}"
    
    elif question.type == 'code':
        code = random.choice(EXAMPLE_CODES)
        # Добавляем случайные комментарии и модификации
        comments = [
            '// Оптимизированная версия',
            '// Требует доработки',
            '// Рабочий вариант',
            '// Экспериментальная версия'
        ]
        return f"{code}\n{random.choice(comments)} (user_{user_id})"
    
    elif question.type == 'matching':
        options = json.loads(question.options)
        matches = list(range(len(options)))
        random.shuffle(matches)
        return [str(i) for i in matches]
    
    return ''

def calculate_score(answers, questions):
    """Расчет случайного, но правдоподобного балла на основе ответов"""
    total_possible = len(questions)
    base_score = random.uniform(0.4, 0.9)  # Базовый уровень успешности
    question_scores = []
    
    for q in questions:
        if q.id in answers:
            # Генерируем случайный балл для каждого вопроса
            score = random.uniform(base_score - 0.2, base_score + 0.2)
            score = max(0, min(1, score))  # Ограничиваем значением от 0 до 1
            question_scores.append(score)
    
    if not question_scores:
        return 0
    
    # Считаем средний балл и масштабируем его до максимального возможного
    avg_score = sum(question_scores) / len(question_scores)
    return round(avg_score * total_possible, 1)

def fill_test_data():
    with app.app_context():
        # Используем существующих пользователей
        admin = User.query.filter_by(role='admin').first()
        experts = User.query.filter_by(role='expert').all()
        working_group = User.query.filter_by(role='working_group').all()
        
        all_users = [admin] + experts + working_group
        print(f'Найдено пользователей: админ - 1, экспертов - {len(experts)}, рабочая группа - {len(working_group)}')

        # Заполняем результаты оценки для всех пользователей
        blocks = AssessmentBlock.query.all()
        
        for user in all_users:
            for block in blocks:
                # Пропускаем, если уже есть результат
                existing = AssessmentResult.query.filter_by(user_id=user.id, block_id=block.id).first()
                if existing:
                    continue

                # Особая обработка для блока взаимооценки
                if block.id == 4 or 'Взаимооценка' in block.name:
                    answers = {}
                    total_score = 0
                    other_users = [u for u in all_users if u.id != user.id]
                    
                    # Каждый пользователь оценивает всех остальных
                    for other in other_users:
                        # Генерируем более реалистичные оценки (5-10)
                        score = random.randint(5, 10)
                        answers[str(other.id)] = str(score)
                        total_score += score
                        
                        # Создаём PeerEvaluation
                        existing_peer = PeerEvaluation.query.filter_by(
                            evaluator_id=user.id,
                            evaluated_id=other.id
                        ).first()
                        if not existing_peer:
                            # Создаем словарь с критериями оценки
                            criteria = {
                                "опыт": random.randint(5, 10),
                                "знания": random.randint(5, 10),
                                "коммуникабельность": random.randint(5, 10),
                                "эффективность": random.randint(5, 10)
                            }
                            
                            evaluation = PeerEvaluation(
                                evaluator_id=user.id,
                                evaluated_id=other.id,
                                score=score,
                                criteria_scores=json.dumps(criteria)  # Добавляем критерии оценки
                            )
                            db.session.add(evaluation)
                    
                    # Рассчитываем средний балл и нормализуем его к максимальному баллу блока
                    avg_score = total_score / len(other_users) if other_users else 0
                    # Средний балл сейчас в диапазоне 0-10, нормализуем к максимальному баллу блока
                    normalized_score = (avg_score / 10) * block.max_score
                    
                    result = AssessmentResult(
                        user_id=user.id,
                        block_id=block.id,
                        score=normalized_score,
                        answers=json.dumps(answers, ensure_ascii=False)
                    )
                    db.session.add(result)
                    
                else:
                    # Обработка остальных блоков
                    questions = AssessmentQuestion.query.filter_by(block_id=block.id).all()
                    answers = {}
                    
                    # Отвечаем на все вопросы
                    for q in questions:
                        ans = random_answer(q, user.id)
                        answers[str(q.id)] = ans if isinstance(ans, str) else json.dumps(ans)
                    
                    # Генерируем баллы как процент от максимально возможного для блока
                    max_possible = block.max_score
                    min_percent = 0.15  # Минимум 15% от максимального балла
                    max_percent = 0.85  # Максимум 85% от максимального балла
                    
                    # Для экспертов и админа генерируем более высокие баллы
                    if user.role in ['expert', 'admin']:
                        min_percent = 0.30  # Минимум 30% от максимального балла
                    
                    # Рассчитываем финальный балл как процент от максимального
                    percent = random.uniform(min_percent, max_percent)
                    total_score = round(max_possible * percent, 1)
                    
                    result = AssessmentResult(
                        user_id=user.id,
                        block_id=block.id,
                        score=total_score,
                        answers=json.dumps(answers, ensure_ascii=False)
                    )
                    db.session.add(result)
                
                db.session.commit()

        # Экспертные оценки кода
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
                
                # Каждый эксперт оценивает код
                for expert in experts:
                    if expert.id == result.user_id:
                        continue
                        
                    existing = ExpertCodeEvaluation.query.filter_by(
                        assessment_result_id=result.id,
                        question_id=question.id,
                        expert_id=expert.id
                    ).first()
                    
                    if not existing:
                        # Генерируем более разнообразные комментарии
                        comments = [
                            "Код хорошо структурирован, но есть возможности для оптимизации",
                            "Требуется улучшение обработки краевых случаев",
                            "Отличная реализация, понятная документация",
                            "Код работает, но нужно улучшить читаемость",
                            "Хорошее решение, но можно сделать более эффективно"
                        ]
                        
                        # Генерируем более высокие оценки (5-10)
                        evaluation = ExpertCodeEvaluation(
                            assessment_result_id=result.id,
                            question_id=question.id,
                            expert_id=expert.id,
                            score=random.randint(5, 10),
                            comments=random.choice(comments),
                            date=datetime.utcnow()
                        )
                        db.session.add(evaluation)
                        
        db.session.commit()
        print('Тестовые данные успешно добавлены!')

if __name__ == '__main__':
    fill_test_data() 