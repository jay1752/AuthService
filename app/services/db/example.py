"""
Example of how to use the MySQL client.

How to set up and test:
1. Run migrations inside container:
   $ docker exec -it auth_service python migrations/run.py

2. Test database connection and queries:
   $ docker exec -it auth_service python -m app.services.db.example

Migration output example:
```
2025-05-04 18:08:19,769 - INFO - MySQL connection pool initialized: mysql:3306/bf
2025-05-04 18:08:19,779 - INFO - Created migrations table
2025-05-04 18:08:19,779 - INFO - Found 0 previously executed migrations
2025-05-04 18:08:19,780 - INFO - Found 1 migration files
2025-05-04 18:08:19,780 - INFO - Executing 1 pending migrations
2025-05-04 18:08:19,780 - INFO - Running migration: 001_create_buildings_table.sql
2025-05-04 18:08:19,801 - INFO - Migration 001_create_buildings_table.sql executed successfully
2025-05-04 18:08:19,801 - INFO - All migrations completed successfully
2025-05-04 18:08:19,801 - INFO - MySQL connection pool closed
```
"""

import asyncio
from app.services.db.mysql_client import mysql_client

async def example_usage():
    """Example of how to use the MySQL client."""
    
    # Initialize the connection pool
    await mysql_client.initialize()
    
    try:
        # Example SELECT query
        buildings = await mysql_client.select("SELECT * FROM buildings LIMIT 10")
        print(f"Found {len(buildings)} buildings")
        
        # Example SELECT ONE query
        building = await mysql_client.select_one("SELECT * FROM buildings WHERE id = %s", (1,))
        if building:
            print(f"Found building: {building['name']}")
        
        # Example INSERT query
        building_id = await mysql_client.insert(
            "buildings",
            {
                "name": "Tech Center Tower",
                "address": "123 Innovation Blvd",
                "city": "Boston",
                "state": "MA",
                "zip_code": "02110",
                "total_floors": 25,
                "building_type": "commercial"
            }
        )
        print(f"Inserted building with ID: {building_id}")
        
        # Example UPDATE query
        updated = await mysql_client.update(
            "buildings",
            {"name": "Tech Innovation Center", "total_floors": 26},
            "id = %s",
            (building_id,)
        )
        print(f"Updated {updated} row(s)")
        
        # Example INSERT for related table
        amenity_id = await mysql_client.insert(
            "building_amenities",
            {
                "building_id": building_id,
                "name": "Rooftop Garden",
                "description": "Open air garden with seating areas and Wi-Fi"
            }
        )
        print(f"Added amenity with ID: {amenity_id}")
        
        # Example DELETE query
        deleted = await mysql_client.delete("buildings", "id = %s", (building_id,))
        print(f"Deleted {deleted} row(s) (and related amenities via cascade)")
        
        # Example transaction
        await mysql_client.execute_transaction([
            ("INSERT INTO buildings (name, address, city, state, zip_code, total_floors, building_type) VALUES (%s, %s, %s, %s, %s, %s, %s)", 
             ("Transaction Tower", "456 Database St", "Seattle", "WA", "98101", 15, "commercial")),
            ("INSERT INTO building_amenities (building_id, name, description) VALUES (LAST_INSERT_ID(), %s, %s)", 
             ("Fitness Center", "24/7 access gym with modern equipment"))
        ])
        print("Transaction completed successfully")
        
    finally:
        # Close the connection pool
        await mysql_client.close()

if __name__ == "__main__":
    asyncio.run(example_usage()) 