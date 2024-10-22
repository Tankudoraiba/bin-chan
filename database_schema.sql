CREATE TABLE texts (
    id VARCHAR(40) PRIMARY KEY,
    content TEXT NOT NULL,
    expiry TIMESTAMP NOT NULL,
    is_encrypted BOOLEAN DEFAULT FALSE
);
