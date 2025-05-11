import sqlite3
import json
import os

def print_table_schema(cursor, table_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()
    print(f"\nTable '{table_name}' schema:")
    for col in columns:
        print(f"  {col[1]} ({col[2]}){' PRIMARY KEY' if col[5] else ''}")

def print_table_content(cursor, table_name):
    # Get column names
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [col[1] for col in cursor.fetchall()]
    
    cursor.execute(f"SELECT * FROM {table_name}")
    rows = cursor.fetchall()
    print(f"\nTable '{table_name}' content ({len(rows)} rows):")
    
    # Print column headers
    print("  " + " | ".join(columns))
    print("  " + "-" * (len(" | ".join(columns)) + 2))
    
    # Print rows
    for row in rows:
        formatted_values = []
        for val in row:
            if isinstance(val, str) and len(val) > 50:
                formatted_values.append(val[:47] + "...")
            else:
                formatted_values.append(str(val))
        print(f"  {' | '.join(formatted_values)}")

def check_database():
    try:
        # Connect to database
        conn = sqlite3.connect('quiz.db')
        cursor = conn.cursor()
        
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print("\nTables in database:")
        for table in tables:
            print(f"- {table[0]}")
            
        # Check assessment blocks
        print("\nAssessment Blocks:")
        cursor.execute("SELECT id, name, description, weight, max_score FROM assessment_block;")
        blocks = cursor.fetchall()
        for block in blocks:
            print(f"Block {block[0]}: {block[1]}")
            print(f"  Description: {block[2]}")
            print(f"  Weight: {block[3]}")
            print(f"  Max Score: {block[4]}")
            
        # Check assessment questions
        print("\nAssessment Questions:")
        cursor.execute("SELECT id, block_id, type, text FROM assessment_question;")
        questions = cursor.fetchall()
        for question in questions:
            print(f"Question {question[0]} (Block {question[1]}):")
            print(f"  Type: {question[2]}")
            print(f"  Text: {question[3][:100]}...")
            
        # Check users
        print("\nUsers:")
        cursor.execute("SELECT id, username, role FROM user;")
        users = cursor.fetchall()
        for user in users:
            print(f"User {user[0]}: {user[1]} (Role: {user[2]})")
            
    except Exception as e:
        print(f"Error checking database: {str(e)}")
    finally:
        conn.close()

def main():
    print("\nDatabase Check Script")
    print("=" * 20)
    
    try:
        # Get absolute path to the database
        db_path = os.path.abspath('quiz.db')
        print(f"\nDatabase Information:")
        print(f"Path: {db_path}")
        print(f"Exists: {os.path.exists(db_path)}")
        
        if not os.path.exists(db_path):
            print("\nError: Database file not found!")
            return
            
        print(f"Size: {os.path.getsize(db_path):,} bytes")
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        if not tables:
            print("\nNo tables found in the database.")
            print("\nChecking database integrity...")
            cursor.execute("PRAGMA integrity_check")
            integrity = cursor.fetchone()
            print(f"Integrity check result: {integrity[0]}")
        else:
            print("\nFound Tables:", ", ".join([table[0] for table in tables]))
            
            # Print schema and content for each table
            for table in tables:
                table_name = table[0]
                print_table_schema(cursor, table_name)
                print_table_content(cursor, table_name)
        
    except sqlite3.Error as e:
        print(f"\nSQLite error occurred: {e}")
        print(f"Error class: {e.__class__.__name__}")
    except Exception as e:
        print(f"\nUnexpected error occurred: {e}")
        print(f"Error class: {e.__class__.__name__}")
    finally:
        if 'conn' in locals():
            conn.close()
        print("\nDatabase check completed.\n")

if __name__ == "__main__":
    check_database() 