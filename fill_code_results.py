import os
import sys
import json
from datetime import datetime
import importlib.util

# Динамический импорт моделей из 1.py
spec = importlib.util.spec_from_file_location("models", os.path.join(os.path.dirname(__file__), "1.py"))
models = importlib.util.module_from_spec(spec)
spec.loader.exec_module(models)

app = models.app
db = models.db
User = models.User
AssessmentBlock = models.AssessmentBlock
AssessmentQuestion = models.AssessmentQuestion
AssessmentResult = models.AssessmentResult

# --- Конфигурация ---
USER = {'username': 'Миша', 'password': 'Миша', 'role': 'user'}

BLOCK = {
    'name': 'Базовое программирование',
    'description': 'Блок для проверки основных навыков программирования'
}

QUESTION = {
    'type': 'code',
    'text': 'Напишите функцию, возвращающую сумму двух чисел',
    'points': 10,
    'code_template': 'def add(a, b):\n    # Ваш код здесь',
    'test_cases': json.dumps([
        {'input': '1 2', 'expected': '3'},
        {'input': '5 7', 'expected': '12'}
    ])
}

USER_CODE = 'def add(a, b):\n    return a + b'

if __name__ == '__main__':
    with app.app_context():
        # 1. Создать пользователя Миша
        user = User.query.filter_by(username=USER['username']).first()
        if not user:
            user = User(username=USER['username'], role=USER['role'])
            user.set_password(USER['password'])
            db.session.add(user)
            db.session.commit()
            print('Пользователь Миша создан')
        else:
            print('Пользователь Миша уже существует')

        # 2. Создать блок
        block = AssessmentBlock.query.filter_by(name=BLOCK['name']).first()
        if not block:
            block = AssessmentBlock(**BLOCK)
            db.session.add(block)
            db.session.commit()
            print('Блок создан')
        else:
            print('Блок уже существует')

        # 3. Создать вопрос типа code
        question = AssessmentQuestion.query.filter_by(block_id=block.id, type='code').first()
        if not question:
            question = AssessmentQuestion(
                block_id=block.id,
                type=QUESTION['type'],
                text=QUESTION['text'],
                points=QUESTION['points'],
                code_template=QUESTION['code_template'],
                test_cases=QUESTION['test_cases']
            )
            db.session.add(question)
            db.session.commit()
            print('Вопрос создан')
        else:
            print('Вопрос уже существует')

        # 4. Создать результат с кодом только для Миши
        result = AssessmentResult.query.filter_by(user_id=user.id, block_id=block.id).first()
        if not result:
            answers = {str(question.id): USER_CODE}
            result = AssessmentResult(
                user_id=user.id,
                block_id=block.id,
                score=0,
                date=datetime.utcnow(),
                answers=json.dumps(answers)
            )
            db.session.add(result)
            db.session.commit()
            print('Результат с кодом для Миши создан!')
        else:
            print('У Миши уже есть результат с кодом.')

        print('Готово! Теперь вы можете зайти под экспертом и увидеть задание для оценки кода от Миши.') 