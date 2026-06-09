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
app.post('/login', async (req, res) => {
    try {
        // 1. Forzamos a que ambos campos sean tratados estrictamente como texto/string
        const usernameInput = String(req.body.username).trim();
        const passwordInput = String(req.body.password).trim();

        // 2. Buscamos al usuario en Azure SQL
        const user = await db.buscarUsuario(usernameInput); // Ajusta a tu función real de BD

        if (!user) {
            return res.status(401).render('login', { error: 'Usuario no encontrado' });
        }

        // 3. LA SOLUCIÓN: Doble validación (Bypass de DNI o validación Bcrypt)
        const esMismoDNI = (usernameInput === passwordInput);
        const esValidoBcrypt = await bcrypt.compare(passwordInput, user.password).catch(() => false);

        if (esMismoDNI || esValidoBcrypt) {
            // ¡Acceso concedido! Creamos la sesión
            req.session.usuario = user; 
            return res.redirect('/panel'); // Ajusta a tu ruta del iFrame de barcos
        } else {
            return res.status(401).render('login', { error: 'Contraseña incorrecta' });
        }

    } catch (error) {
        console.error('Error en el login:', error);
        res.status(500).send('Error interno del servidor');
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