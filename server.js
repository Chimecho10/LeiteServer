require('dotenv').config();
const mysql = require('mysql2/promise');
const path = require('path');
const express = require('express');
const cors = require('cors');
const {google} = require('googleapis');
const {OAuth2Client} = require('google-auth-library'); 

const app = express();

app.use(cors());
app.use(express.json());

const CLIENT_ID = '393566517581-gauak01rkd9lqdil81lo4j87d6agmdq0.apps.googleusercontent.com';
const googleClient = new OAuth2Client(CLIENT_ID)

const credenciais = JSON.parse(process.env.GOOGLE_CREDENCIAIS_JSON);

const auth = new google.auth.GoogleAuth({
  credentials: credenciais,
  scopes: ['https://www.googleapis.com/auth/drive'],
});

const drive = google.drive({ version: 'v3', auth });
const cache = {};
const buscaCache = {}; // Guarda o tempo em que a primeira pessoa acessou depois do tempo ter cabado
const temporizador = 18000000; // 5 Horas

const pool = mysql.createPool({
  uri: process.env.DATABASE_URL,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

async function verificarConta(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer '))
    {return res.status(401).send('Acesso Negado');}

  const token = authHeader.split(' ')[1]

  try 
    {const ticket = await googleClient.verifyIdToken({idToken: token, audience: CLIENT_ID,}) 
     const payload = ticket.getPayload();
     const email = payload.email.toLowerCase();

     const [linhas] = await pool.execute('SELECT email, is_admin FROM usuarios WHERE email = ?', [email]);

     if(linhas.length > 0)
          {req.usuarioEmail = email;
           next();} 
     else
          {res.status(403).send('Acesso Negado: Email não autorizado.')}}
  catch(error)
    {res.status(401).send('Acesso Negado: Token inválido');}}

app.post('/api/databaseaddemail', verificarConta, async (req, res) => {
  try{
    const [linhas] = await pool.execute('SELECT email, is_admin FROM usuarios WHERE email = ?', [req.usuarioEmail]);
    
    if (!linhas[0].is_admin){
      return res.status(403).json({erro: 'Acesso negado, apenas administradores podem adicionar novos emails.'});
    }

    const {novoEmail} = req.body;
    if (!novoEmail)
      {return res.status(400).json({erro: 'Nenhum email foi fornecido'});}

    const [resultado] = await pool.execute('INSERT IGNORE INTO usuarios (email) VALUES (?)', [novoEmail]);
    if (resultado.affectedRows === 0)
      {return res.status(409).json({mensagem: 'Email já está no sistema.'});}
    
    return res.status(201).json({mensagem: 'Email autorizado com sucesso!'});
  }
  catch (error){
    console.error('Erro ao adicionar email:', error);
    return res.status(500).json({erro: 'Erro interno do servidor.'});
  }
})

app.get('/api/buscaremail', verificarConta, async (req, res) => {
  try{
    const [verificat] = await pool.execute('SELECT email, is_admin FROM usuarios WHERE email = ?', [req.usuarioEmail]);
    
    if (!verificat[0].is_admin){
      return res.status(403).json({erro: 'Acesso negado, apenas administradores podem buscar usuários.'});
    }

    const dadoenviado = req.query.email

    if (dadoenviado.length === 0 || !dadoenviado){
      return res.status(400).json({erro: 'Campo vazio!'});
    }

    const [linhas] = await pool.execute(
      'SELECT id, email, is_admin, nome, matricula FROM usuarios WHERE email = ? OR nome = ? OR matricula = ?',
      [dadoenviado, dadoenviado, dadoenviado]
    );

    if (linhas.length === 0){
     return res.status(404).json({ erro: 'Usuário Não Encontrado' });
    }

     return res.status(200).json(linhas);
  }
  catch (error){
    console.error('Erro de requisição: ', error);
    return res.status(500).json({erro: 'Erro interno ao buscar usuário'});
  }
})

app.delete('/api/deletaruser', verificarConta, async (req, res) => {
  try{
    const [verificat] = await pool.execute('SELECT email, is_admin FROM usuarios WHERE email = ?', [req.usuarioEmail]);
    
    if (!verificat[0].is_admin){
      return res.status(403).json({erro: 'Acesso negado, apenas administradores podem buscar usuários.'});
    }

    const id = req.body.id;

    if (!id){
      return res.status(400).json({erro: 'Usuário não fornecido!'});
    }

    const [linhas] = await pool.execute('DELETE FROM usuarios WHERE id = ?', [id]);

    if (linhas.affectedRows === 0){
     return res.status(404).json({erro: 'Usuário Não Encontrado' });
    }

    return res.status(200).json({mensagem: 'Usuário Deletado com Sucesso!'});

  }
  catch (error){
    console.error('Erro de requisição: ', error);
    return res.status(500).json({erro: 'Erro interno ao deletar usuário'});
  }
})

app.post('/api/adduser', verificarConta, async (req, res) => {
  try{
    const [verificat] = await pool.execute('SELECT email, is_admin FROM usuarios WHERE email = ?', [req.usuarioEmail]);
    
    if (!verificat[0].is_admin){
      return res.status(403).json({erro: 'Acesso negado, apenas administradores podem adicionar usuários.'});
    }

    const { nome, email, matricula } = req.body;

    const apenasNumeros = /^[0-9]+$/;
    if (!apenasNumeros.test(matricula)) {
      return res.status(400).json({ erro: 'A matrícula deve conter apenas números!' });
    }

    if (!nome || nome.trim() === '' || !email || email.trim() === '' || !matricula || matricula.trim() === ''){
      return res.status(400).json({erro: 'Campos em branco!'});
    }

    const [linhas] = await pool.execute('INSERT INTO usuarios (email, nome, matricula) VALUES (?, ?, ?)',
                                       [email, nome, matricula]);

    return res.status(201).json({mensagem: 'Usuário cadastrado com sucesso!'});
  }
  catch (error){
    console.error('Erro ao adicionar usuário: ', error);
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ erro: 'Este e-mail já está em uso por outro usuário.' });
    }
    return res.status(500).json({erro: 'Erro interno ao adicionar usuário'});
  }
})

app.put('/api/salvaruser', verificarConta, async (req, res) => {
  try{
    const [verificat] = await pool.execute('SELECT email, is_admin FROM usuarios WHERE email = ?', [req.usuarioEmail]);
    
    if (!verificat[0].is_admin){
      return res.status(403).json({erro: 'Acesso negado, apenas administradores podem alterar usuários.'});
    }

    const { id, nome, email, matricula, is_admin } = req.body;

    const apenasNumeros = /^[0-9]+$/;
    if (!apenasNumeros.test(matricula)) {
      return res.status(400).json({ erro: 'A matrícula deve conter apenas números!' });
    }

    if (!id || !nome || nome.trim() === '' || !email || email.trim() === '' || !matricula || matricula.trim() === '' || is_admin === undefined || is_admin === null){
      return res.status(400).json({erro: 'Usuário não fornecido ou campos em branco!'});
    }

    const [linhas] = await pool.execute('UPDATE usuarios SET email = ?, is_admin = ?, nome = ?, matricula = ? WHERE id = ?', 
                                       [email, is_admin, nome, matricula, id]);

    if (linhas.affectedRows === 0){
     return res.status(404).json({erro: 'Usuário não Encontrado'});
    }

    return res.status(200).json({mensagem: 'Usuário alterado com Sucesso!'});

  }
  catch (error){
    console.error('Erro de requisição: ', error);
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ erro: 'Este e-mail já está em uso por outro usuário.' });
    }
    return res.status(500).json({erro: 'Erro interno ao alterar usuário'});
  }
})

app.get('/api/verifica', async (req, res) =>{
  const email = req.query.email;
  
  if (!email) 
    {return res.status(400).json({autorizado: false, admin: false})}

  console.log("Tentativa de Login: ", email);

  try {
    const [linhas] = await pool.execute('SELECT email, is_admin FROM usuarios WHERE email = ?', [email]);

    if (linhas.length > 0)
      {console.log("Login com Sucesso: ", email);
       const ehAdmin = Boolean(linhas[0].is_admin);
       return res.json({autorizado: true, admin: ehAdmin});}
    else
      {console.log("Login sem Sucesso:", email);
       res.json({autorizado: false, admin: false});}}
       
  catch (error){
    console.log(`Erro no Sistema (Banco de Dados) para ${email}:`, erro.message);
    res.status(500).json({autorizado: false, erro: "Erro no Servidor"})
  }})

app.get('/api/analisaemail', verificarConta, async (req, res) => {
  try {
    const [linhas] = await pool.execute('SELECT email, is_admin FROM usuarios WHERE email = ?', [req.usuarioEmail]);

    if (linhas.length > 0 && linhas[0].is_admin)
      {return res.json({okay: true})}
    else 
      {return res.status(403).json({erro: 'Acesso Negado. Não é Adm.'});}
  }
  catch (error){
    return res.status(500).json({erro: 'Erro no servidor'});
  }
})

app.get('/api/arquivos', verificarConta, async (req, res) => {
  try {
    const folderId = req.query.folderId || '1Mx5NjkXrjH8Il9HhziITDjNAIZk2BMlK';
    const agora = Date.now();

    if (cache[folderId] && (agora - buscaCache[folderId] < temporizador)){
      return res.json(cache[folderId])
    }

    const response = await drive.files.list({
      q: `'${folderId}' in parents and trashed = false`,
      fields: 'files(id, name, mimeType)', 
      orderBy: 'folder, name'
    });

    const responseDataFiles = response.data.files;

    cache[folderId] = responseDataFiles;
    buscaCache[folderId] = Date.now();
    res.json(responseDataFiles);

  } catch (error) {
    console.error("Erro ao listar arquivos do Drive:", error.message);
    res.status(500).send('Erro ao listar os arquivos.');
  }
});

app.get('/api/arquivos/:fileId', verificarConta, async (req, res) => {
  const { fileId } = req.params;

  const email = req.usuarioEmail;
  const abrindoOuBaixando = req.query.abrindoOuBaixando || 'acessou';

  try {
    const fileMetadata = await drive.files.get({
      fileId: fileId,
      fields: 'name, mimeType'
    });

    const fileName = fileMetadata.data.name;

    if (abrindoOuBaixando === 'abrindo')
      {console.log(`${email} abriu o arquivo: ${fileName}`);}
    else
      {console.log(`${email} baixou o arquivo: ${fileName}`);}

    const response = await drive.files.get(
      { fileId: fileId, alt: 'media' },
      { responseType: 'stream' }
    );

    res.setHeader('Content-Type', fileMetadata.data.mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${fileMetadata.data.name}"`);

    response.data
      .on('error', err => {
        console.error('Erro no fluxo de download:', err);
        res.status(500).send('Erro ao processar o arquivo.');
      })
      .pipe(res);

  } catch (error) {
    console.error("Erro ao baixar do Drive:", error.message);
    res.status(500).send('Erro ao resgatar o arquivo.');
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server ligado na porta ${PORT}!`);
});
