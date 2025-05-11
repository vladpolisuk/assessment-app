from app import db, Question, app
import json
from questions.block1 import frontend_questions
from questions.block2 import qualimetric_questions
from questions.block3 import creativity_questions
from questions.block4 import self_evaluation_questions
from questions.block5 import peer_evaluation_questions

def init_questions():
    # Добавляем все вопросы в базу данных
    all_questions = (frontend_questions + qualimetric_questions + 
                    creativity_questions + self_evaluation_questions + 
                    peer_evaluation_questions)

    for q in all_questions:
        # Преобразуем списки в JSON строки
        q['options'] = json.dumps(q['options'])
        q['correct_answer'] = json.dumps(q['correct_answer'])
        
        question = Question(**q)
        db.session.add(question)

    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_questions() 