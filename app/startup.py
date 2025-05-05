import logging
import asyncio
from app.services.db import mysql_client

logger = logging.getLogger(__name__)

async def startup_db_handler():
    """Initialize the MySQL client on application startup."""
    # Add retry logic for database connection
    max_retries = 5
    retry_delay = 5  # seconds
    
    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Attempting to connect to MySQL (attempt {attempt}/{max_retries})...")
            await mysql_client.initialize()
            logger.info("MySQL client initialized successfully")
            return
        except Exception as e:
            if attempt < max_retries:
                logger.warning(f"Failed to initialize MySQL client: {e}. Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
            else:
                logger.error(f"Failed to initialize MySQL client after {max_retries} attempts: {e}")
                raise

async def shutdown_db_handler():
    """Close the MySQL client on application shutdown."""
    try:
        await mysql_client.close()
        logger.info("MySQL client closed successfully")
    except Exception as e:
        logger.error(f"Error closing MySQL client: {e}") 