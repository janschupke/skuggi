-- First-boot seed for Helix (runs once on an empty data volume).
CREATE TABLE employees (
    id     SERIAL PRIMARY KEY,
    name   TEXT NOT NULL,
    email  TEXT NOT NULL,
    dept   TEXT NOT NULL,
    salary INTEGER NOT NULL
);
INSERT INTO employees (name, email, dept, salary) VALUES
('Rita Okonkwo', 'r.okonkwo@helix.example', 'Engineering', 121000),
('Dieter Vogel', 'd.vogel@helix.example', 'Sales', 98000),
('Sofia Marchetti', 's.marchetti@helix.example', 'Executive', 210000);
