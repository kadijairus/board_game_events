CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    creator_id INTEGER NOT NULL,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    address TEXT NOT NULL,
    place TEXT NOT NULL,
    lng DECIMAL(11, 8) NOT NULL,
    lat DECIMAL(10, 8) NOT NULL,
    games TEXT NOT NULL,
    date DATE NOT NULL,
    time TIME,
    participants INTEGER NOT NULL,
    comments TEXT,
    link TEXT,
    FOREIGN KEY (creator_id) REFERENCES users (id)
);

CREATE TABLE users (
	id	INTEGER PRIMARY KEY AUTOINCREMENT,
	username	TEXT NOT NULL UNIQUE,
	email	TEXT NOT NULL UNIQUE,
	password_hash	TEXT NOT NULL UNIQUE,
    is_admin	BOOLEAN NOT NULL
);

CREATE TABLE events_reg (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_id INTEGER,
    UNIQUE (user_id, event_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (event_id) REFERENCES events(id)
);
