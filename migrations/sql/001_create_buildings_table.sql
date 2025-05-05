-- Create buildings table
CREATE TABLE IF NOT EXISTS buildings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    address VARCHAR(255) NOT NULL,
    city VARCHAR(100) NOT NULL,
    state VARCHAR(50) NOT NULL,
    country VARCHAR(50) NOT NULL DEFAULT 'USA',
    zip_code VARCHAR(20) NOT NULL,
    latitude DECIMAL(10, 8) NULL,
    longitude DECIMAL(11, 8) NULL,
    total_floors INT NOT NULL DEFAULT 1,
    year_built INT NULL,
    total_area_sqft DECIMAL(12, 2) NULL,
    building_type ENUM('residential', 'commercial', 'industrial', 'mixed_use', 'other') NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes for faster lookups
    INDEX idx_building_name (name),
    INDEX idx_building_city (city),
    INDEX idx_building_type (building_type),
    INDEX idx_building_active (is_active)
);

-- Create building_amenities table for storing multiple amenities per building
CREATE TABLE IF NOT EXISTS building_amenities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    building_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Foreign key to buildings table
    CONSTRAINT fk_building_amenities_building_id
        FOREIGN KEY (building_id)
        REFERENCES buildings (id)
        ON DELETE CASCADE,
        
    -- Unique constraint to prevent duplicate amenities for a building
    UNIQUE KEY unique_building_amenity (building_id, name)
);

-- Insert sample data into buildings table
INSERT INTO buildings (
    name, 
    address, 
    city, 
    state, 
    country,
    zip_code, 
    latitude, 
    longitude, 
    total_floors, 
    year_built, 
    total_area_sqft, 
    building_type
) VALUES 
('Empire State Building', '350 Fifth Avenue', 'New York', 'NY', 'USA', '10118', 40.748817, -73.985428, 102, 1931, 2248355, 'commercial'),
('Willis Tower', '233 S Wacker Dr', 'Chicago', 'IL', 'USA', '60606', 41.878876, -87.635915, 108, 1973, 4477800, 'commercial'),
('Burj Khalifa', '1 Sheikh Mohammed bin Rashid Blvd', 'Dubai', 'Dubai', 'UAE', '00000', 25.197197, 55.274376, 163, 2010, 3331100, 'mixed_use'),
('Transamerica Pyramid', '600 Montgomery St', 'San Francisco', 'CA', 'USA', '94111', 37.795053, -122.403286, 48, 1972, 530000, 'commercial');

-- Insert sample amenities
INSERT INTO building_amenities (building_id, name, description) VALUES
(1, 'Observation Deck', '86th and 102nd floor observation decks with panoramic views of New York City'),
(1, 'Restaurants', 'Multiple dining options available'),
(2, 'Skydeck', 'Glass balcony extending 4 feet outside the 103rd floor'),
(3, 'At the Top', 'Observation deck on the 124th, 125th, and 148th floors'),
(3, 'Armani Hotel', 'Luxury hotel occupying 15 of the lower 39 floors'),
(4, 'Conference Center', 'Meeting and event spaces available for rent'); 