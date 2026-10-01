const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mysql = require('mysql2/promise');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: process.env.FRONTEND_URL || "http://localhost:3000",
        credentials: true
    }
});

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true
}));

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10
});

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

// --- AUTHENTICATION MIDDLEWARE ---
const verifyToken = (req, res, next) => {
    const token = req.cookies.token || req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized access' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// --- AUTH API ROUTES ---
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword]);
        res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
    } catch (err) {
        res.status(500).json({ error: 'Email already exists or server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) return res.status(400).json({ error: 'Invalid credentials' });

        const user = users[0]; // 🔍 MUST BE users[0]
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
        
        // Ensure cookie options are explicitly set for localhost development
        res.cookie('token', token, { 
            httpOnly: true, 
            secure: false, // false for HTTP localhost
            sameSite: 'lax', // Recommended for cross-port requests
            maxAge: 7 * 24 * 60 * 60 * 1000 
        });
        
        res.json({ message: 'Logged in successfully', user: { id: user.id, name: user.name, email: user.email } });
    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).json({ error: 'Login error' });
    }
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out successfully' });
});

app.get('/api/auth/me', verifyToken, async (req, res) => {
    res.json({ user: req.user });
});

// --- PRESENTATION & SESSION MANAGEMENT APIS ---
app.get('/api/sessions', verifyToken, async (req, res) => {
    try {
        const [sessions] = await db.query('SELECT * FROM sessions WHERE host_id = ? ORDER BY created_at DESC', [req.user.id]);
        res.json(sessions);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch sessions' });
    }
});

app.post('/api/sessions', verifyToken, async (req, res) => {
    try {
        const { title } = req.body;
        const passcode = Math.floor(100000 + Math.random() * 900000).toString();
        const [result] = await db.query('INSERT INTO sessions (host_id, title, passcode, is_active) VALUES (?, ?, ?, ?)', [req.user.id, title, passcode, false]);
        res.status(201).json({ sessionId: result.insertId, title, passcode });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create session' });
    }
});

app.get('/api/sessions/:passcode', async (req, res) => {
    try {
        const { passcode } = req.params;
        const [sessions] = await db.query('SELECT * FROM sessions WHERE passcode = ?', [passcode]);
        if (sessions.length === 0) return res.status(404).json({ error: 'Session not found' });
        
        const session = sessions[0]; // ✅ Correctly access first session element
        const [questions] = await db.query('SELECT * FROM questions WHERE session_id = ? ORDER BY question_order ASC', [session.id]);
        for (let q of questions) {
            const [opts] = await db.query('SELECT * FROM options WHERE question_id = ?', [q.id]);
            q.options = opts;
        }
        res.json({ session, questions });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error fetching session details' });
    }
});

app.delete('/api/sessions/:id', verifyToken, async (req, res) => {
    try {
        await db.query('DELETE FROM sessions WHERE id = ? AND host_id = ?', [req.params.id, req.user.id]);
        res.json({ message: 'Session deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete session' });
    }
});

// --- QUESTION MANAGEMENT APIS ---
app.post('/api/sessions/:sessionId/questions', verifyToken, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const { question_text, question_type, options } = req.body;

        const [[{ maxOrder }]] = await db.query('SELECT MAX(question_order) as maxOrder FROM questions WHERE session_id = ?', [sessionId]);
        const nextOrder = (maxOrder || 0) + 1;

        const [qRes] = await db.query('INSERT INTO questions (session_id, question_text, question_type, question_order) VALUES (?, ?, ?, ?)', [sessionId, question_text, question_type || 'multiple_choice', nextOrder]);
        const questionId = qRes.insertId;

        if (options && options.length > 0) {
            for (let optText of options) {
                if (optText.trim()) {
                    await db.query('INSERT INTO options (question_id, option_text) VALUES (?, ?)', [questionId, optText]);
                }
            }
        }
        res.status(201).json({ message: 'Question added', questionId });
    } catch (err) {
        res.status(500).json({ error: 'Failed to add question' });
    }
});

app.delete('/api/questions/:id', verifyToken, async (req, res) => {
    try {
        await db.query('DELETE FROM questions WHERE id = ?', [req.params.id]);
        res.json({ message: 'Question deleted' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete question' });
    }
});

app.get('/api/sessions/:sessionId/stats', verifyToken, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const [questions] = await db.query('SELECT id, question_text FROM questions WHERE session_id = ?', [sessionId]);
        const stats = [];
        for (let q of questions) {
            const [[{ totalVotes }]] = await db.query('SELECT COUNT(*) as totalVotes FROM responses WHERE question_id = ?', [q.id]);
            stats.push({ questionId: q.id, questionText: q.question_text, totalVotes });
        }
        res.json({ stats });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

// --- SOCKET.IO REAL-TIME PRESENTATION SYNC ---
io.on('connection', (socket) => {
    socket.on('join_session', (passcode) => {
        socket.join(passcode);
    });

    // Presenter controls: Start session, change state, move question index
    socket.on('host_control', async ({ passcode, action, payload }) => {
        try {
            if (action === 'start_session') {
                await db.query('UPDATE sessions SET is_active = TRUE WHERE passcode = ?', [passcode]);
            } else if (action === 'end_session') {
                await db.query('UPDATE sessions SET is_active = FALSE WHERE passcode = ?', [passcode]);
            } else if (action === 'update_question_state') {
                await db.query('UPDATE questions SET current_state = ? WHERE id = ?', [payload.state, payload.questionId]);
            } else if (action === 'set_active_question') {
                await db.query('UPDATE sessions SET current_question_index = ? WHERE passcode = ?', [payload.index, passcode]);
            }
            io.to(passcode).emit('session_updated', { action, payload });
        } catch (err) {
            console.error('Socket host control error:', err);
        }
    });

    // Participant submitting answer
    socket.on('submit_answer', async ({ questionId, optionId, answerText, nickname, passcode, userIdentifier }) => {
        try {
            // Check if already voted
            const [existing] = await db.query('SELECT * FROM responses WHERE question_id = ? AND user_identifier = ?', [questionId, userIdentifier]);
            if (existing.length > 0) {
                // Update response if needed or ignore
                await db.query('UPDATE responses SET option_id = ?, answer_text = ?, nickname = ? WHERE question_id = ? AND user_identifier = ?', [optionId || null, answerText || null, nickname || 'Anonymous', questionId, userIdentifier]);
            } else {
                await db.query('INSERT INTO responses (question_id, option_id, answer_text, nickname, user_identifier) VALUES (?, ?, ?, ?, ?)', [questionId, optionId || null, answerText || null, nickname || 'Anonymous', userIdentifier]);
            }

            // Fetch live results distribution
            const [results] = await db.query('SELECT option_id, answer_text, COUNT(*) as count FROM responses WHERE question_id = ? GROUP BY option_id, answer_text', [questionId]);
            io.to(passcode).emit('live_results_updated', { questionId, results });
        } catch (err) {
            console.error('Submit answer error:', err);
        }
    });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`MentiClone backend running on http://localhost:${PORT}`);
});