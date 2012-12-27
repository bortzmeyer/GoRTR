DROP TABLE Events;
DROP TABLE Prefixes;

CREATE TABLE Events (
    id SERIAL UNIQUE NOT NULL,
    time TIMESTAMP NOT NULL,
    server TEXT NOT NULL,
    event TEXT NOT NULL,
    serialNo INTEGER -- if NULL, serial number unknown (typically at the beginning of a session)
);

CREATE TABLE Prefixes (
    id SERIAL UNIQUE NOT NULL,
    time TIMESTAMP NOT NULL,
    announce BOOLEAN, -- FALSE if withdraw
    prefix CIDR,
    maxLength INTEGER, -- if NULL, use the length of the prefix
    serialNo INTEGER -- if NULL, serial number unknown (typically at the beginning of a session)
);
