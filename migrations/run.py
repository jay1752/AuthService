#!/usr/bin/env python
import os
import sys
import argparse
import asyncio
import logging
from typing import List, Optional

# Add project root to sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from app.services.db.mysql_client import mysql_client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Path to SQL migrations directory
MIGRATIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sql")

async def get_executed_migrations() -> List[str]:
    """Get a list of already executed migrations from the database."""
    try:
        # Check if migrations table exists
        exists_query = """
        SELECT COUNT(*) as count FROM information_schema.tables 
        WHERE table_schema = DATABASE() AND table_name = 'migrations'
        """
        result = await mysql_client.select_one(exists_query)
        
        if not result or result['count'] == 0:
            # Create migrations table if it doesn't exist
            create_table_query = """
            CREATE TABLE migrations (
                id INT AUTO_INCREMENT PRIMARY KEY,
                filename VARCHAR(255) NOT NULL,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_filename (filename)
            )
            """
            await mysql_client.execute(create_table_query)
            logger.info("Created migrations table")
            return []
        
        # Get executed migrations
        query = "SELECT filename FROM migrations ORDER BY id"
        results = await mysql_client.select(query)
        return [row['filename'] for row in results]
        
    except Exception as e:
        logger.error(f"Error getting executed migrations: {e}")
        raise

async def mark_migration_executed(filename: str) -> None:
    """Mark a migration as executed in the database."""
    try:
        query = "INSERT INTO migrations (filename) VALUES (%s)"
        await mysql_client.execute(query, (filename,))
    except Exception as e:
        logger.error(f"Error marking migration as executed: {e}")
        raise

async def run_migration_file(filepath: str, filename: str) -> None:
    """Run a single migration file."""
    logger.info(f"Running migration: {filename}")
    
    try:
        # Read SQL file content
        with open(filepath, 'r') as f:
            sql_content = f.read()
        
        # Split into individual statements (assuming statements end with semicolon)
        statements = [stmt.strip() for stmt in sql_content.split(';') if stmt.strip()]
        
        # Begin transaction
        conn = await mysql_client.get_connection()
        try:
            await conn.begin()
            cursor = await conn.cursor()
            
            # Execute each statement
            for stmt in statements:
                if stmt:
                    await cursor.execute(stmt)
            
            # Mark migration as executed
            await cursor.execute("INSERT INTO migrations (filename) VALUES (%s)", (filename,))
            
            # Commit transaction
            await conn.commit()
            logger.info(f"Migration {filename} executed successfully")
            
        except Exception as e:
            await conn.rollback()
            logger.error(f"Error executing migration {filename}: {e}")
            raise
        finally:
            await cursor.close()
            await mysql_client.release_connection(conn)
            
    except Exception as e:
        logger.error(f"Failed to run migration {filename}: {e}")
        raise

async def run_migrations(specific_file: Optional[str] = None) -> None:
    """Run all pending migrations or a specific migration."""
    try:
        # Initialize MySQL client
        await mysql_client.initialize()
        
        # Get executed migrations
        executed_migrations = await get_executed_migrations()
        logger.info(f"Found {len(executed_migrations)} previously executed migrations")
        
        # Get all migration files
        if not os.path.exists(MIGRATIONS_DIR):
            os.makedirs(MIGRATIONS_DIR)
            logger.info(f"Created migrations directory: {MIGRATIONS_DIR}")
        
        all_migration_files = sorted([f for f in os.listdir(MIGRATIONS_DIR) if f.endswith('.sql')])
        logger.info(f"Found {len(all_migration_files)} migration files")
        
        if specific_file:
            # Run a specific migration
            specific_file_with_ext = f"{specific_file}.sql" if not specific_file.endswith('.sql') else specific_file
            if specific_file_with_ext not in all_migration_files:
                logger.error(f"Migration file {specific_file_with_ext} not found in {MIGRATIONS_DIR}")
                return
            
            filepath = os.path.join(MIGRATIONS_DIR, specific_file_with_ext)
            await run_migration_file(filepath, specific_file_with_ext)
            
        else:
            # Run all pending migrations
            pending_migrations = [f for f in all_migration_files if f not in executed_migrations]
            
            if not pending_migrations:
                logger.info("No pending migrations to execute")
                return
            
            logger.info(f"Executing {len(pending_migrations)} pending migrations")
            
            for migration_file in pending_migrations:
                filepath = os.path.join(MIGRATIONS_DIR, migration_file)
                await run_migration_file(filepath, migration_file)
                
            logger.info("All migrations completed successfully")
    
    except Exception as e:
        logger.error(f"Migration process failed: {e}")
        raise
    finally:
        # Close MySQL client
        await mysql_client.close()

def main():
    parser = argparse.ArgumentParser(description="Run database migrations")
    parser.add_argument("--file", "-f", help="Run a specific migration file (without .sql extension)")
    parser.add_argument("--list", "-l", action="store_true", help="List all migration files")
    args = parser.parse_args()
    
    if args.list:
        # Just list the migration files
        if not os.path.exists(MIGRATIONS_DIR):
            print(f"Migrations directory does not exist: {MIGRATIONS_DIR}")
            return
            
        files = sorted([f for f in os.listdir(MIGRATIONS_DIR) if f.endswith('.sql')])
        if not files:
            print("No migration files found")
            return
            
        print(f"Found {len(files)} migration files:")
        for file in files:
            print(f"  - {file}")
        return
    
    # Run migrations
    asyncio.run(run_migrations(args.file))

if __name__ == "__main__":
    main() 