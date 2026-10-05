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
        origin: "https://menti-clone-frontend-2.onrender.com",
        credentials: true
    }
});

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: "https://menti-clone-frontend-2.onrender.com",
    credentials: true
}));

const db = mysql.createPool({
    host: "mysql-21c41bb1-ggits-53e0.k.aivencloud.com",
    port: 25951,
    user: "avnadmin",
    password: "AVNS_o8lQY2UB10CVDD5OZjN",
    database: "defaultdb",

    waitForConnections: true,
    connectionLimit: 10,

    ssl: {
        rejectUnauthorized: false
    }
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

        const [users] = await db.query(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(400).json({
                error: 'Invalid credentials'
            });
        }

        const user = users[0];

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(400).json({
                error: 'Invalid credentials'
            });
        }

        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                name: user.name
            },
            JWT_SECRET,
            {
                expiresIn: '7d'
            }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'none',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({
            message: 'Logged in successfully',
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });

    } catch (err) {
        console.error('Login Error:', err);

        res.status(500).json({
            error: 'Login error'
        });
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

        console.log(`--> FETCHING SESSION FOR PASSCODE: ${passcode}`);

        // Get session
        const [sessions] = await db.query(
            'SELECT * FROM sessions WHERE passcode = ?',
            [passcode]
        );

        if (sessions.length === 0) {
            return res.status(404).json({
                error: 'Session not found'
            });
        }

        const session = sessions[0];

        // Get questions
        const [questions] = await db.query(
            `SELECT *
             FROM questions
             WHERE session_id = ?
             ORDER BY question_order ASC`,
            [session.id]
        );

        // Store initial vote results
        const initialResults = {};

        // Get options and votes
        for (const q of questions) {
            const [results] = await db.query(
                `SELECT
            option_id,
            answer_text,
            COUNT(*) AS count
         FROM responses
         WHERE question_id = ?
         GROUP BY option_id, answer_text`,
                [q.id]
            );

            const [opts] = await db.query(
                `SELECT
            o.*,
            COUNT(r.id) AS vote_count
         FROM options o
         LEFT JOIN responses r
            ON o.id = r.option_id
         WHERE o.question_id = ?
         GROUP BY o.id
         ORDER BY o.id ASC`,
                [q.id]
            );

            // Use opts here, NOT results
            q.options = opts.map(opt => ({
                ...opt,
                vote_count: Number(opt.vote_count) || 0
            }));

            const resultMap = {};

            q.options.forEach(opt => {
                resultMap[opt.id] = opt.vote_count;
            });

            initialResults[q.id] = resultMap;
        }


        console.log(
            '--> INITIAL RESULTS:',
            JSON.stringify(initialResults, null, 2)
        );

        // IMPORTANT
        // Send initialResults to frontend
        const responseData = {
            session,
            questions,
            initialResults
        };

        console.log(
            '--> FINAL RESPONSE:',
            JSON.stringify(responseData, null, 2)
        );

        return res.status(200).json(responseData);

    } catch (err) {
        console.error('--> ERROR FETCHING SESSION:', err);

        return res.status(500).json({
            error: 'Error fetching session details'
        });
    }
});



// ==========================================
// 1. ADD A NEW QUESTION & ITS OPTIONS
// ==========================================
app.post('/api/questions', verifyToken, async (req, res) => {
    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        const { session_id, question_text, question_type, question_order, options } = req.body;

        // Insert into questions table
        const [questionResult] = await connection.query(
            `INSERT INTO questions (session_id, question_text, question_type, question_order, current_state) 
             VALUES (?, ?, ?, ?, 'active')`,
            [session_id, question_text, question_type || 'multiple_choice', question_order || 1]
        );

        const questionId = questionResult.insertId;

        // Insert options if provided
        if (options && Array.isArray(options) && options.length > 0) {
            const optionValues = options.map(optText => [questionId, optText]);
            await connection.query(
                `INSERT INTO options (question_id, option_text) VALUES ?`,
                [optionValues]
            );
        }

        await connection.commit();
        connection.release();

        return res.status(201).json({ 
            message: 'Question added successfully', 
            questionId 
        });

    } catch (err) {
        await connection.rollback();
        connection.release();
        console.error('--> ERROR ADDING QUESTION:', err);
        return res.status(500).json({ error: 'Failed to add question' });
    }
});


// ==========================================
// 2. EDIT A QUESTION & SYNC OPTIONS
// ==========================================
app.put('/api/questions/:id', verifyToken, async (req, res) => {
    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        const { id } = req.params;
        const { question_text, question_type, options } = req.body;

        // Update question details
        await connection.query(
            `UPDATE questions SET question_text = ?, question_type = ? WHERE id = ?`,
            [question_text, question_type || 'multiple_choice', id]
        );

        // Handle options update: Simple approach is to clear old options and insert new ones 
        // (Note: This will cascade-delete responses if foreign key constraints are set with ON DELETE CASCADE, 
        // otherwise ensure you handle existing responses safely)
        if (options && Array.isArray(options)) {
            // Optional: Delete existing options or selectively update. 
            // Here we delete old options to cleanly re-insert the updated list.
            await connection.query(`DELETE FROM options WHERE question_id = ?`, [id]);

            if (options.length > 0) {
                const optionValues = options.map(optText => [id, optText]);
                await connection.query(
                    `INSERT INTO options (question_id, option_text) VALUES ?`,
                    [optionValues]
                );
            }
        }

        await connection.commit();
        connection.release();

        return res.status(200).json({ message: 'Question updated successfully' });

    } catch (err) {
        await connection.rollback();
        connection.release();
        console.error('--> ERROR UPDATING QUESTION:', err);
        return res.status(500).json({ error: 'Failed to update question' });
    }
});


// ==========================================
// 3. TOGGLE QUESTION ACTIVE STATE ('active' / 'inactive')
// ==========================================
app.patch('/api/questions/:id/state', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { current_state } = req.body; // expected 'active' or 'inactive'

        if (!['active', 'inactive'].includes(current_state)) {
            return res.status(400).json({ error: 'Invalid state value. Use "active" or "inactive".' });
        }

        await db.query(
            `UPDATE questions SET current_state = ? WHERE id = ?`,
            [current_state, id]
        );

        return res.status(200).json({ message: `Question state updated to ${current_state}` });

    } catch (err) {
        console.error('--> ERROR UPDATING QUESTION STATE:', err);
        return res.status(500).json({ error: 'Failed to update question state' });
    }
});


// ==========================================
// 4. DELETE A QUESTION
// ==========================================
app.delete('/api/questions/:id', verifyToken,  async (req, res) => {
    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        const { id } = req.params;

        // Delete options and responses first if foreign keys don't handle cascade deletion automatically
        await connection.query(`DELETE FROM responses WHERE question_id = ?`, [id]);
        await connection.query(`DELETE FROM options WHERE question_id = ?`, [id]);
        await connection.query(`DELETE FROM questions WHERE id = ?`, [id]);

        await connection.commit();
        connection.release();

        return res.status(200).json({ message: 'Question deleted successfully' });

    } catch (err) {
        await connection.rollback();
        connection.release();
        console.error('--> ERROR DELETING QUESTION:', err);
        return res.status(500).json({ error: 'Failed to delete question' });
    }
});


// ==========================================
// 5. REORDER / SERIALIZE QUESTION SEQUENCES
// ==========================================
app.patch('/api/sessions/:sessionId/reorder', async (req, res) => {
    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        const { questions } = req.body; // Expects an array of objects: [{ id, question_order }, ...]

        if (!questions || !Array.isArray(questions)) {
            return res.status(400).json({ error: 'Invalid questions payload for reordering' });
        }

        for (const q of questions) {
            await connection.query(
                `UPDATE questions SET question_order = ? WHERE id = ?`,
                [q.question_order, q.id]
            );
        }

        await connection.commit();
        connection.release();

        return res.status(200).json({ message: 'Question sequences updated successfully' });

    } catch (err) {
        await connection.rollback();
        connection.release();
        console.error('--> ERROR REORDERING QUESTIONS:', err);
        return res.status(500).json({ error: 'Failed to reorder questions' });
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

// app.get('/api/sessions/:sessionId/stats', verifyToken, async (req, res) => {
//     try {
//         const { sessionId } = req.params;
//         const [questions] = await db.query('SELECT id, question_text FROM questions WHERE session_id = ?', [sessionId]);
//         const stats = [];
//         for (let q of questions) {
//             const [[{ totalVotes }]] = await db.query('SELECT COUNT(*) as totalVotes FROM responses WHERE question_id = ?', [q.id]);
//             stats.push({ questionId: q.id, questionText: q.question_text, totalVotes });
//         }
//         res.json({ stats });
//     } catch (err) {
//         res.status(500).json({ error: 'Failed to fetch statistics' });
//     }
// });



app.get('/api/sessions/:passcode/stats', verifyToken, async (req, res) => {
    try {
        const { passcode } = req.params;

        // DEBUG: Check what user is making the request
        console.log("User ID:", req.user?.id, "Passcode:", passcode);

        const [sessions] = await db.query(
            `SELECT id, title, passcode FROM sessions WHERE passcode = ? AND host_id = ?`,
            [passcode, req.user.id]
        );

        console.log("Found sessions:", sessions);

        if (sessions.length === 0) {
            return res.status(404).json({ error: 'Session not found or unauthorized' });
        }

        const sessionId = sessions[0].id;
        const session = sessions[0];

        // Get questions
        const [questions] = await db.query(
            `SELECT
                id,
                question_text,
                question_type,
                question_order,
                current_state
             FROM questions
             WHERE session_id = ?
             ORDER BY question_order ASC`,
            [sessionId]
        );

        const stats = [];

        for (const question of questions) {

            // Total responses
            const [[responseCount]] = await db.query(
                `SELECT COUNT(*) AS totalVotes
                 FROM responses
                 WHERE question_id = ?`,
                [question.id]
            );

            // Unique participants
            const [[participantCount]] = await db.query(
                `SELECT COUNT(DISTINCT user_identifier) AS uniqueParticipants
                 FROM responses
                 WHERE question_id = ?`,
                [question.id]
            );

            // Get options and their votes
            const [options] = await db.query(
                `SELECT
                    o.id,
                    o.option_text,
                    (
                        SELECT COUNT(*)
                        FROM responses r
                        WHERE r.option_id = o.id
                        AND r.question_id = ?
                    ) AS votes
                 FROM options o
                 WHERE o.question_id = ?
                 ORDER BY o.id ASC`,
                [question.id, question.id]
            );

            stats.push({
                questionId: question.id,
                questionText: question.question_text,
                questionType: question.question_type,
                questionOrder: question.question_order,

                totalVotes: Number(responseCount.totalVotes),

                uniqueParticipants: Number(
                    participantCount.uniqueParticipants
                ),

                options: options.map(option => ({
                    id: option.id,
                    option_text: option.option_text,
                    votes: Number(option.votes)
                }))
            });
        }

        // Total unique participants for the session
        const [[participantTotal]] = await db.query(
            `SELECT COUNT(DISTINCT r.user_identifier) AS totalParticipants
             FROM responses r
             INNER JOIN questions q
                ON q.id = r.question_id
             WHERE q.session_id = ?`,
            [sessionId]
        );

        res.json({
            session,
            totalParticipants: Number(
                participantTotal.totalParticipants
            ),
            totalQuestions: questions.length,
            stats
        });

    } catch (err) {
        console.error('Stats error:', err);

        res.status(500).json({
            error: 'Failed to fetch statistics'
        });
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