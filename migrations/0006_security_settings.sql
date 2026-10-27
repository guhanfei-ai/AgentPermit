-- 不设置共享初始密码。首次设置由管理员以自己的登录密码确认。
CREATE TABLE security_settings (
 id INTEGER PRIMARY KEY CHECK (id = 1),
 holiday_unlock_password_hash TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL
);
INSERT INTO security_settings(id, updated_at) VALUES (1, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
