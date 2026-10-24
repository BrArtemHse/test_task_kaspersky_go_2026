CREATE TABLE threats (
    md5 TEXT PRIMARY KEY NOT NULL CHECK (length(md5) = 32 AND md5 NOT GLOB '*[^a-f0-9]*'),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 4096),
    category TEXT NOT NULL DEFAULT 'unknown' CHECK (category IN ('unknown','virus','trojan','ransomware','spyware','worm','adware','other')),
    severity TEXT NOT NULL DEFAULT 'unknown' CHECK (severity IN ('unknown','low','medium','high','critical')),
    first_seen TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
