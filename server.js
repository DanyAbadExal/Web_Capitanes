require('dotenv').config();
const express = require('express');
const sql = require('mssql'); // Conector oficial de Microsoft SQL Server
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de conexión protegida por variables de entorno (.env)
const dbConfig = {
    user: process.env.AZURE_SQL_USER,
    password: process.env.AZURE_SQL_PASSWORD,
    server: process.env.AZURE_SQL_SERVER, 
    database: process.env.AZURE_SQL_DATABASE,
    authentication: {
        type: 'default'
    },
    options: {
        encrypt: true, // Requerido obligatoriamente por Azure SQL
        trustServerCertificate: false
    }
};

// 1. RUTA DE LOGIN REAL CON AZURE SQL
app.post('/api/login', async (req, res) => {
    const username = String(req.body.username).trim();
    const password = String(req.body.password).trim();
    const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
        // Abrir conexión con Azure
        let pool = await sql.connect(dbConfig);
        
        // Consultar si el usuario existe en la tabla de Azure
        let result = await pool.request()
            .input('inputUser', sql.VarChar, username)
            .input('inputPass', sql.VarChar, password)
            .query('SELECT username FROM Usuarios WHERE username = @inputUser AND password = @inputPass');

        if (result.recordset.length > 0) {
            const user = result.recordset[0];

            // REGISTRO REAL EN LA TABLA DE HISTORIAL DE AZURE
            await pool.request()
                .input('username', sql.VarChar, user.username)
                .input('ip', sql.VarChar, userIp)
                .query('INSERT INTO HistorialAccesos (username, ip_cliente) VALUES (@username, @ip)');

            // Crear cookie de sesión segura
            res.cookie('session_user', user.username, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
            return res.json({ success: true });
        } else {
            return res.json({ success: false, message: 'Usuario o contraseña incorrectos.' });
        }
    } catch (err) {
        console.error('⚠️ Error de conexión con Azure SQL:', err.message);
        return res.status(500).json({ success: false, message: 'Error de comunicación con la base de datos de Azure.' });
    }
});

// 2. RUTA DEL HISTÓRICO REAL DESDE AZURE SQL
app.get('/api/historico', async (req, res) => {
    try {
        let pool = await sql.connect(dbConfig);
        let result = await pool.request()
            .query('SELECT TOP 100 username, fecha_ingreso, ip_cliente FROM HistorialAccesos ORDER BY fecha_ingreso DESC');
        
        res.json({
            descripcion: "Historial de accesos en tiempo real (Desde Azure SQL)",
            total_registros: result.recordset.length,
            registros: result.recordset
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 3. CONFIGURACIÓN DEL REPORTE
app.get('/api/report-config', (req, res) => {
    const sessionUser = req.cookies.session_user;
    if (!sessionUser) return res.status(401).json({ success: false, message: 'No autorizado' });

    res.json({
        success: true,
        username: sessionUser,
        iframeUrl: "https://app.powerbi.com/view?r=eyJrIjoiNzc1MWFiOGUtMDAzNS00OWRkLWJmYjktYzliYTI5NjU0MTNjIiwidCI6IjI4ZGViYmNkLWQzY2ItNGRjNS05MTVjLTM1NWIyOWQ2NTVmNSIsImMiOjR9&pageName=08d76d34b4a8e0689b88"
    });
});

// 4. CERRAR SESIÓN
app.get('/api/logout', (req, res) => {
    res.clearCookie('session_user');
    res.json({ success: true });
});

// 5. RUTA RAÍZ
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor de producción conectado a la lógica de Azure listo.`);
});