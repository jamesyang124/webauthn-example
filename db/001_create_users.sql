INSERT INTO users (username, email, password_hash) VALUES
('user1', 'user1@example.com', crypt('password1', gen_salt('bf'))),
('user2', 'user2@example.com', crypt('password2', gen_salt('bf'))),
('user3', 'user3@example.com', crypt('password3', gen_salt('bf'))),
('user4', 'user4@example.com', crypt('password4', gen_salt('bf'))),
('user5', 'user5@example.com', crypt('password5', gen_salt('bf'))),
('user6', 'user6@example.com', crypt('password6', gen_salt('bf'))),
('user7', 'user7@example.com', crypt('password7', gen_salt('bf'))),
('user8', 'user8@example.com', crypt('password8', gen_salt('bf'))),
('user9', 'user9@example.com', crypt('password9', gen_salt('bf'))),
('user10', 'user10@example.com', crypt('password10', gen_salt('bf')));
