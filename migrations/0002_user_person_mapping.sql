ALTER TABLE users ADD COLUMN person_id TEXT;
CREATE INDEX IF NOT EXISTS users_person_id ON users(person_id);
