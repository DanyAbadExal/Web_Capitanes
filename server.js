// Despliegue de producción v1.0.1 - Control de Flota
require('dotenv').config();
const express = require('express');
const sql = require('mssql'); 
const cookieParser = require('cookie-parser');
const path = require('path');
const bcrypt = require('bcryptjs'); // 1. Importamos la librería de seguridad

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
        encrypt: true, 
        trustServerCertificate: false
    }
};

// 1. RUTA DE LOGIN REFORMADA CON COMPARACIÓN SEGURA (BCRYPT)
app.post('/api/login', async (req, res) => {
    const username = String(req.body.username).trim();
    const password = String(req.body.password).trim();
    const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
        let pool = await sql.connect(dbConfig);
        
        // Buscamos al usuario únicamente por su DNI (username) para traer su hash
        let result = await pool.request()
            .input('inputUser', sql.VarChar, username)
            .query('SELECT username, password, nombre, apellido, posicion, celular, embarcacion FROM Usuarios WHERE username = @inputUser');

        if (result.recordset.length > 0) {
            const user = result.recordset[0];

            // 2. Comparamos la contraseña web con el hash seguro guardado en la BD
            const contraseniaCorrecta = await bcrypt.compare(password, user.password);

            if (contraseniaCorrecta) {
                // Formateamos la información requerida para la cabecera web
                const identificadorPantalla = `${user.nombre} ${user.apellido} | EP: ${user.embarcacion}`;

                // REGISTRO EN LA TABLA DE HISTORIAL DE AZURE
                await pool.request()
                    .input('username', sql.VarChar, user.username)
                    .input('ip', sql.VarChar, userIp)
                    .query('INSERT INTO HistorialAccesos (username, ip_cliente) VALUES (@username, @ip)');

                // Guardamos la sesión en la cookie
                res.cookie('session_user', identificadorPantalla, { 
                    httpOnly: true, 
                    secure: process.env.NODE_ENV === 'production' 
                });
                
                return res.json({ success: true });
            }
        }
        
        // Por seguridad, devolvemos el mismo error si el usuario no existe o si la clave está mal
        return res.json({ success: false, message: 'Usuario o contraseña incorrectos.' });

    } catch (err) {
        console.error('⚠️ Error de conexión con Azure SQL:', err.message);
        return res.status(500).json({ success: false, message: 'Error de comunicación con la base de datos de Azure.' });
    }
});

// 2. RUTA DEL HISTÓRICO REAL CON DETALLE DE PERFILES (INNER JOIN)
app.get('/api/historico', async (req, res) => {
    try {
        let pool = await sql.connect(dbConfig);
        
        let result = await pool.request()
            .query(`
                SELECT TOP 100 
                    h.fecha_ingreso, 
                    h.ip_cliente,
                    u.username AS dni,
                    CONCAT(u.nombre, ' ', u.apellido) AS nombre_completo,
                    u.posicion,
                    u.celular,
                    u.embarcacion
                FROM HistorialAccesos h
                INNER JOIN Usuarios u ON h.username = u.username
                ORDER BY h.fecha_ingreso DESC
            `);
        
        res.json({
            descripcion: "Historial de accesos en tiempo real con datos de perfil (Desde Azure SQL)",
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
        iframeUrl: "https://app.powerbi.com/view?r=eyJrIjoiMWQxMjgyN2MtOWRkZC00ODZkLTg4MDQtOTQ5NTdjYTM3MmZiIiwidCI6IjI4ZGViYmNkLWQzY2ItNGRjNS05MTVjLTM1NWIyOWQ2NTVmNSIsImMiOjR9"
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

// INICIAR SERVIDOR
app.listen(PORT, () => {
    console.log(`🚀 Servidor de producción ciberseguro conectado a Azure listo.`);
});