import os
import logging
import asyncio
from typing import Any, Dict, List, Optional, Union, Tuple

import aiomysql
from aiomysql import Pool, Connection, Cursor

logger = logging.getLogger(__name__)

class MySQLClient:
    """Simple async MySQL client for database operations."""
    
    _instance = None
    _pool = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    async def initialize(self) -> None:
        """Initialize the connection pool."""
        if self._pool is None or self._pool.closed:
            # Get connection parameters from environment variables or use defaults
            host = os.getenv("DB_HOST", "mysql")
            port = int(os.getenv("DB_PORT", "3306"))
            user = os.getenv("DB_USER", "root")
            password = os.getenv("DB_PASSWORD", "rootpassword")
            database = os.getenv("DB_NAME", "bf")
            
            self._pool = await aiomysql.create_pool(
                host=host,
                port=port,
                user=user,
                password=password,
                db=database,
                autocommit=True,
                minsize=1,
                maxsize=10,
            )
            logger.info(f"MySQL connection pool initialized: {host}:{port}/{database}")
    
    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool and not self._pool.closed:
            self._pool.close()
            await self._pool.wait_closed()
            logger.info("MySQL connection pool closed")
    
    async def get_connection(self) -> Connection:
        """Get a connection from the pool."""
        if self._pool is None or self._pool.closed:
            await self.initialize()
        return await self._pool.acquire()
    
    async def release_connection(self, conn: Connection) -> None:
        """Release a connection back to the pool."""
        if self._pool and not self._pool.closed:
            self._pool.release(conn)
    
    async def select(self, query: str, params: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Execute a SELECT query and return all results as a list of dictionaries.
        
        Args:
            query: SQL query string
            params: Query parameters as a tuple
            
        Returns:
            List of dictionaries where each dictionary represents a row
        """
        conn = None
        try:
            conn = await self.get_connection()
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute(query, params or ())
                return await cursor.fetchall()
        except Exception as e:
            logger.error(f"Error executing SELECT query: {e}")
            raise
        finally:
            if conn:
                await self.release_connection(conn)
    
    async def select_one(self, query: str, params: Optional[tuple] = None) -> Optional[Dict[str, Any]]:
        """Execute a SELECT query and return the first result as a dictionary.
        
        Args:
            query: SQL query string
            params: Query parameters as a tuple
            
        Returns:
            Dictionary representing the first row or None if no results
        """
        conn = None
        try:
            conn = await self.get_connection()
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute(query, params or ())
                return await cursor.fetchone()
        except Exception as e:
            logger.error(f"Error executing SELECT_ONE query: {e}")
            raise
        finally:
            if conn:
                await self.release_connection(conn)
    
    async def insert(self, table: str, data: Dict[str, Any]) -> int:
        """Insert a single row into a table.
        
        Args:
            table: Table name
            data: Dictionary of column names and values
            
        Returns:
            Last row ID or 0 if not available
        """
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["%s"] * len(data))
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        values = tuple(data.values())
        
        conn = None
        try:
            conn = await self.get_connection()
            async with conn.cursor() as cursor:
                await cursor.execute(query, values)
                return cursor.lastrowid or 0
        except Exception as e:
            logger.error(f"Error executing INSERT query: {e}")
            raise
        finally:
            if conn:
                await self.release_connection(conn)
    
    async def insert_many(self, table: str, data_list: List[Dict[str, Any]]) -> int:
        """Insert multiple rows into a table.
        
        Args:
            table: Table name
            data_list: List of dictionaries containing column names and values
            
        Returns:
            Number of rows affected
        """
        if not data_list:
            return 0
            
        columns = ", ".join(data_list[0].keys())
        placeholders = ", ".join(["%s"] * len(data_list[0]))
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        values = [tuple(data.values()) for data in data_list]
        
        conn = None
        try:
            conn = await self.get_connection()
            async with conn.cursor() as cursor:
                await cursor.executemany(query, values)
                return cursor.rowcount
        except Exception as e:
            logger.error(f"Error executing INSERT_MANY query: {e}")
            raise
        finally:
            if conn:
                await self.release_connection(conn)
    
    async def update(self, table: str, data: Dict[str, Any], where: str, where_params: tuple) -> int:
        """Update rows in a table.
        
        Args:
            table: Table name
            data: Dictionary of column names and values to update
            where: WHERE clause of the query
            where_params: Parameters for the WHERE clause
            
        Returns:
            Number of rows affected
        """
        set_clause = ", ".join([f"{col} = %s" for col in data.keys()])
        query = f"UPDATE {table} SET {set_clause} WHERE {where}"
        values = tuple(data.values()) + where_params
        
        conn = None
        try:
            conn = await self.get_connection()
            async with conn.cursor() as cursor:
                await cursor.execute(query, values)
                return cursor.rowcount
        except Exception as e:
            logger.error(f"Error executing UPDATE query: {e}")
            raise
        finally:
            if conn:
                await self.release_connection(conn)
    
    async def delete(self, table: str, where: str, where_params: tuple) -> int:
        """Delete rows from a table.
        
        Args:
            table: Table name
            where: WHERE clause of the query
            where_params: Parameters for the WHERE clause
            
        Returns:
            Number of rows affected
        """
        query = f"DELETE FROM {table} WHERE {where}"
        
        conn = None
        try:
            conn = await self.get_connection()
            async with conn.cursor() as cursor:
                await cursor.execute(query, where_params)
                return cursor.rowcount
        except Exception as e:
            logger.error(f"Error executing DELETE query: {e}")
            raise
        finally:
            if conn:
                await self.release_connection(conn)
    
    async def execute(self, query: str, params: Optional[tuple] = None) -> int:
        """Execute a query that doesn't return rows.
        
        Args:
            query: SQL query string
            params: Query parameters as a tuple
            
        Returns:
            Number of rows affected
        """
        conn = None
        try:
            conn = await self.get_connection()
            async with conn.cursor() as cursor:
                await cursor.execute(query, params or ())
                return cursor.rowcount
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            raise
        finally:
            if conn:
                await self.release_connection(conn)
    
    async def execute_transaction(self, queries: List[Tuple[str, Optional[tuple]]]) -> None:
        """Execute multiple queries in a transaction.
        
        Args:
            queries: List of tuples containing (query, params)
        """
        conn = None
        try:
            conn = await self.get_connection()
            await conn.begin()
            cursor = await conn.cursor()
            
            try:
                for query, params in queries:
                    await cursor.execute(query, params or ())
                await conn.commit()
            except Exception as e:
                await conn.rollback()
                logger.error(f"Error executing transaction, rolled back: {e}")
                raise
            finally:
                await cursor.close()
        except Exception as e:
            logger.error(f"Error in transaction: {e}")
            raise
        finally:
            if conn:
                await self.release_connection(conn)

# Singleton instance
mysql_client = MySQLClient() 