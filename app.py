from flask import render_template
from flask_login import login_required, current_user
from app.models import Assessment

# Добавляем функцию sum в контекст шаблона
def sum_iterable(iterable):
    return sum(iterable)

@app.route('/assessment/results')
@login_required
def assessment_results():
    # Получаем все оценки пользователя
    assessments = Assessment.query.filter_by(user_id=current_user.id).all()
    
    # Подготавливаем данные для графиков
    block_names = []
    avg_scores = []
    score_ranges = ['0-2', '2-4', '4-6', '6-8', '8-10']
    score_counts = [0] * 5
    
    # Собираем статистику по блокам
    for assessment in assessments:
        block_names.append(assessment.block.name)
        avg_scores.append(assessment.score)
        
        # Подсчитываем количество оценок в каждом диапазоне
        score_index = min(int(assessment.score / 2), 4)
        score_counts[score_index] += 1
    
    return render_template('assessment_results.html',
                         assessments=assessments,
                         block_names=block_names,
                         avg_scores=avg_scores,
                         score_ranges=score_ranges,
                         score_counts=score_counts,
                         sum=sum_iterable)  # Передаем функцию sum в шаблон

@app.route('/profile')
@login_required
def profile():
    # Получаем все оценки пользователя
    assessments = Assessment.query.filter_by(user_id=current_user.id).all()
    
    # Вычисляем итоговую оценку
    final_score = 0
    total_weight = 0
    block_scores = {}
    blocks = {}
    
    for assessment in assessments:
        block = assessment.block
        blocks[block.id] = block
        score = (assessment.score / block.max_score) * 100
        block_scores[block.id] = score / 100  # Нормализованный score от 0 до 1
        final_score += score * block.weight
        total_weight += block.weight
    
    if total_weight > 0:
        final_score = final_score / total_weight
    
    # Определяем уровень компетентности
    if final_score >= 90:
        competence_level = 1
    elif final_score >= 75:
        competence_level = 2
    elif final_score >= 60:
        competence_level = 3
    elif final_score >= 40:
        competence_level = 4
    else:
        competence_level = 5
    
    # Получаем оценки от коллег и рабочей группы
    peer_score = 0
    work_group_score = 0
    
    # TODO: Добавить логику получения peer_score и work_group_score
    
    # Подготавливаем данные для отображения результатов по блокам
    block_results = []
    for assessment in assessments:
        block = assessment.block
        score_percentage = (assessment.score / block.max_score) * 100
        block_results.append({
            'block': block,
            'score_percentage': score_percentage,
            'result': assessment
        })
    
    return render_template('profile.html',
                         user=current_user,
                         final_score=final_score,
                         competence_level=competence_level,
                         block_scores=block_scores,
                         blocks=blocks,
                         block_results=block_results,
                         peer_score=peer_score,
                         work_group_score=work_group_score)

@app.route('/assessment/stats')
@login_required
def assessment_stats():
    try:
        # Получаем все оценки, исключая блоки Воспроизводимость и Конформизм
        results = AssessmentResult.query\
            .join(AssessmentBlock)\
            .filter(~AssessmentBlock.name.in_(['Воспроизводимость', 'Конформизм']))\
            .all()
    
        # Получаем все блоки, исключая Воспроизводимость и Конформизм
        blocks = AssessmentBlock.query\
            .filter(~AssessmentBlock.name.in_(['Воспроизводимость', 'Конформизм']))\
            .all()
    
        # Подготавливаем статистику по блокам
        block_stats = {}
        for block in blocks:
            block_results = [r for r in results if r.block_id == block.id]
            if block_results:
                scores = [r.score for r in block_results]
            block_stats[block.id] = {
                    'name': block.name,
                    'avg_score': sum(scores) / len(scores),
                    'max_score': max(scores),
                    'min_score': min(scores),
                    'count': len(scores)
            }
        
        # Подготавливаем данные для графиков
        score_ranges = ['0-20', '21-40', '41-60', '61-80', '81-100']
        score_counts = [0] * len(score_ranges)
        
        for result in results:
            score_percentage = (result.score / result.block.max_score) * 100
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
    
    return render_template('assessment_stats.html',
                         blocks=blocks,
                         block_stats=block_stats,
                         score_ranges=score_ranges,
                         score_counts=score_counts,
                         block_names=block_names,
                         avg_scores=avg_scores) 
    except Exception as e:
        print("Ошибка при загрузке статистики:", e)
        flash('Произошла ошибка при загрузке статистики', 'error')
        return redirect(url_for('index')) 

@app.route('/assessment_system')
@login_required
def assessment_system():    
    try:
        # Define excluded blocks
        excluded_blocks = [
            'Конформизм',
            'Самооценка',
            'Оценка рабочей группой'
        ]
        
        # Get all blocks except the excluded ones
        blocks = AssessmentBlock.query.filter(
            ~AssessmentBlock.name.in_(excluded_blocks)
        ).all()
        
        # For each block get current user's results
        for block in blocks:
            result = AssessmentResult.query.filter_by(
                user_id=session['user_id'],
                block_id=block.id
            ).order_by(AssessmentResult.date.desc()).first()
            
            block.avg_score = result.score if result else None
        
        # Get expert count
        expert_count = User.query.filter_by(role='expert').count()
        
        # If current user is expert, decrease count by 1
        if session.get('role') == 'expert':
            expert_count -= 1
        
        return render_template('assessment_system.html', blocks=blocks, expert_count=expert_count)
    except Exception as e:
        debug_print(f"Ошибка при загрузке блока assessment_system: {str(e)}")
        debug_print(f"Трейс ошибки:\n{traceback.format_exc()}")
        flash('Произошла ошибка при загрузке блока', 'error')
        return redirect(url_for('index')) 

@app.route('/take_assessment')
@login_required
def take_assessment():
    # Define excluded blocks
    excluded_blocks = [
        'Конформизм',
        'Самооценка',
        'Оценка рабочей группой'
    ]
    
    # Get all blocks except the excluded ones
    blocks = AssessmentBlock.query.filter(
        ~AssessmentBlock.name.in_(excluded_blocks)
    ).all()
    
    return render_template('take_assessment.html', blocks=blocks) 