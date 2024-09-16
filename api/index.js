const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const app = express();
const port = 3000;

// Настройки базы данных
const db = new sqlite3.Database(':memory:');

// Создаем таблицу для хранения данных о посещениях
db.run(`
  CREATE TABLE visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    city TEXT,
    device TEXT,
    timestamp TEXT
  )
`);

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Авторизация (для просмотра статистики)
const users = [{ username: 'admin', password: bcrypt.hashSync('password', 8) }];

const generateToken = (username) => jwt.sign({ username }, 'secret', { expiresIn: '1h' });

// Middleware для проверки авторизации
const authMiddleware = (req, res, next) => {
    const token = req.cookies['token'];
    if (!token) return res.redirect('/login');
    try {
        req.user = jwt.verify(token.split(' ')[1], 'secret');
        next();
    } catch (error) {
        res.redirect('/login');
    }
};

// Перенаправление на страницу логина при доступе к корневому маршруту
app.get('/', (req, res) => {
    res.redirect('/login');
});

// Маршрут для отображения страницы логина
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
    console.log(req.body);

    const { username, password } = req.body;
    const user = users.find((u) => u.username === username);

    if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(username);
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/stats');
    } else {
        res.status(401).send('Unauthorized');
    }
});

// Защищенный маршрут для отображения статистики
app.get('/stats', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'stats.html'));
});

// Роут для отслеживания посещений
app.post('/api/track', authMiddleware, (req, res) => {
    const { ip, city, device, timestamp } = req.body;
    db.run(
        `INSERT INTO visits (ip, city, device, timestamp) VALUES (?, ?, ?, ?)`,
        [ip, city, device, timestamp],
        function (err) {
            if (err) return res.status(500).send('Error inserting data');
            res.status(200).send('Visit tracked');
        }
    );
});

// Запрос данных для графиков
app.get('/api/stats', authMiddleware, (req, res) => {
    db.all('SELECT city, strftime("%H", timestamp) as hour, COUNT(*) as count FROM visits GROUP BY city, hour', [], (err, rows) => {
        if (err) return res.status(500).send('Error retrieving data');
        res.json(rows);
    });
});

// Запуск сервера
module.exports = app;