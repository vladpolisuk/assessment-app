from models import db, AssessmentQuestion as Question, AssessmentBlock as Block
from flask import Flask
import json
import os
import re

# Create a temporary Flask application for this script
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

def clean_json_string(s):
    """Clean a JSON string by removing control characters and fixing common issues"""
    # Remove all control characters except \n, \r, \t
    s = ''.join(ch for ch in s if ord(ch) >= 32 or ch in '\n\r\t')
    # Replace any backspace characters (ASCII 8)
    s = s.replace('\b', '')
    # Replace non-breaking spaces with regular spaces
    s = s.replace('\u00A0', ' ')
    # Fix potential quote escaping issues
    s = s.replace('\\"', '"')
    # Fix issues with multiline code blocks
    s = re.sub(r'```[a-z]*\n', '```\n', s)
    return s

def init_questions():
    # Load questions from JSON files in blocks directory
    blocks_data = []
    
    # Check if the blocks directory exists
    if os.path.exists('blocks'):
        # Read all JSON files in the blocks directory
        for filename in os.listdir('blocks'):
            if filename.endswith('.json'):
                file_path = os.path.join('blocks', filename)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Clean the JSON content
                        content = clean_json_string(content)
                        data = json.loads(content)
                        blocks_data.append(data)
                        print(f"Successfully loaded {file_path}")
                except Exception as e:
                    print(f"Error loading {file_path}: {e}")
                    # Try to find the problematic part in the file
                    try:
                        lines = content.split('\n')
                        for i, line in enumerate(lines[:280], 1):
                            try:
                                json.loads(line + '}')
                            except Exception as line_e:
                                if i >= 265 and i <= 275:
                                    print(f"Potential issue at line {i}: {line}")
                    except:
                        pass
    
    if not blocks_data:
        print("No blocks found in blocks directory")
        return
    
    print(f"Loaded {len(blocks_data)} block files")
    
    # First create all the assessment blocks
    for block_data in blocks_data:
        block_name = block_data.get('name')
        if not block_name:
            print(f"Skipping block with no name")
            continue
            
        # Check if block already exists
        existing_block = Block.query.filter_by(name=block_name).first()
        if existing_block:
            print(f"Block '{block_name}' already exists")
            continue
            
        # Create a new block
        block = Block(
            name=block_name,
            description=block_data.get('description', ''),
            weight=block_data.get('weight', 1.0),
            max_score=block_data.get('max_score', 10.0)
        )
        db.session.add(block)
        print(f"Added block: {block_name}")
    
    # Commit blocks to get their IDs
    db.session.commit()
    
    # Now add all questions with the corresponding block_id
    questions_count = 0
    for block_data in blocks_data:
        block_name = block_data.get('name')
        if not block_name:
            continue
            
        # Get the block ID
        block = Block.query.filter_by(name=block_name).first()
        if not block:
            print(f"Block '{block_name}' not found in database")
            continue
            
        # Add all questions for this block
        questions = block_data.get('questions', [])
        for q in questions:
            # Skip questions without required fields
            if 'text' not in q and 'question' not in q or 'type' not in q:
                print(f"Skipping question missing required fields")
                continue
            
            # Handle different field names in different JSON files
            if 'question' in q and 'text' not in q:
                q['text'] = q['question']
                del q['question']
                
            # Convert necessary fields to JSON
            for field in ['options', 'correct_answer', 'test_cases', 'criteria', 
                         'option_scores', 'example_solutions', 'definitions']:
                if field in q and isinstance(q[field], list):
                    q[field] = json.dumps(q[field])
            
            # Set the block_id from the block we found
            q['block_id'] = block.id
            
            # Remove fields not in the model
            fields_to_remove = []
            for field in q:
                if field not in [column.name for column in Question.__table__.columns]:
                    fields_to_remove.append(field)
            
            for field in fields_to_remove:
                del q[field]
            
            # Create question object
            try:
        question = Question(**q)
        db.session.add(question)
                questions_count += 1
            except Exception as e:
                print(f"Error adding question: {e}")
                if len(str(q)) > 200:
                    print(f"Question data too large to display")
                else:
                    print(f"Question data: {q}")

    db.session.commit()
    print(f"Added {questions_count} questions to database")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_questions() 