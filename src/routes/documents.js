require('dotenv').config();
const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const db = require('../../config/database');
const authenticateJWT = require('../middleware/auth');
const authorizeRoles = require('../middleware/rbac');
const logger = require('../../config/logger');
const { title } = require('process');
const { body, validationResult } = require('express-validator');
const crypto = require('crypto');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'a935fe22fd1f0a912aab115a6ab161849ca0d1188cc2dc54209fd8393314ca68'; //Must be 32 bytes
const IV_Length = 16;

function encrypt(buffer) {
    let iv = crypto.randomBytes(IV_Length);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    return Buffer.concat([iv, encrypted]);
}

function decrypt(buffer) {
    const iv = buffer.slice(0,IV_Length);
    const encryptedText = buffer.slice(IV_Length);
    let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    return decrypted;
}

//Ensure uploads directory exists
const uploadsDir = path.join(__dirname,'../../uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true});
}

//GET /api/documents - View all documents (role-based filtering)
router.get('/', authenticateJWT, (req, res) => {
    const userRoleId = req.user.role_id;

    let query;
    if (userRoleId === 1) { //Admin sees all
        query = 'SELECT d.*, u.username as owner FROM Documents d JOIN Users u ON d.owner_id = u.id ORDER BY d.uploaded_at DESC';
    } else{
        query = 'SELECT d.*, u.username as owner FROM Documents d JOIN Users u ON d.owner_id = u.id WHERE d.owner_id = ? ORDER BY d.uploaded_at DESC';
    }

    db.all(query, userRoleId === 1 ? [] : [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({error: 'Database Error'});
        logger.info('Documents list accessed', {
            userId: req.user.role_id,
            username: req.user.username,
            documentCount: rows.length,
            action: 'list'
        });
        res.json({documents: rows});
    });
});

//POST /api/documents - Upload Document (Manager+ can upload)
router.post('/upload', [
    authenticateJWT,
    authorizeRoles('Admin', 'Manager'),
    body('title')
        .trim()
        .notEmpty().withMessage('Document title required')
        .isLength({max: 100}).withMessage('Title too long')
    ],
    async(req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array()});
        }
        if (!req.files || !req.files.document) {
            return res.status(400).json({error: "No file uploaded"});
        }
        const file = req.files.document;
        const {title} = req.body

        //Basic File Validation
        const allowedTypes = ['.pdf', '.docx', '.txt'];
        const fileExt = path.extname(file.name).toLowerCase();
        if (!allowedTypes.includes(fileExt)) {
            return res.status(400).json({ error: 'File Type not allowed'});
        }

        //Encryption
        const fileBuffer = file.data; //Get Buffer density
        const encryptedBuffer = encrypt(fileBuffer); //Encrypt

        const filename = `${Date.now()}_${file.name}.enc`;
        const filepath = path.join(uploadsDir, filename);

        fs.writeFile(filepath, encryptedBuffer, (err) =>{
            if (err){
                logger.error('Encrypted File write failed', {
                    userId: req.user.id,
                    username: req.user.username,
                    filename,
                    error: err.message
                });
                return res.status(500).json({ error: "File upload error"});
            } 
            db.run(
                'INSERT INTO Documents (title, filename, owner_id) VALUES (?, ?, ?)',
                [title, filename, req.user.id],
                function (err) {
                    if (err){
                        logger.error('Document upload DB error',{
                            userId: req.user.id,
                            username: req.user.username,
                            title,
                            filename,
                            error: err.message
                        });
                        return res.status(500).json({ error: 'Database insert failed', details: err.message});
                    }
                    logger.info('Encrypted document uploaded successfully', {
                        userId: req.user.id,
                        username: req.user.username,
                        documentId: this.lastID,
                        title,
                        filename,
                        action: 'upload_encrypted'
                    });
                    res.status(201).json(
                        {
                            message: 'Encrypted document uploaded successfully',
                            document: { id:this.lastID, title, filename}
                        }
                    )
                } 
            );
        });
    }
)

// GET /api/documents/:id/download - Download document (owner or admin)
router.get('/download/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;
    const userId = req.user.id;
    const userRoleId = req.user.role_id;

    db.get(
        'SELECT d.*, u.id as owner_id FROM Documents d JOIN Users u ON d.owner_id = u.id WHERE d.id = ?',
        [id],
        (err, doc) => {
            if (err || !doc) return res.status(404).json({ error: "Document not found" }); 
            
            // Check ownership or admin access
            if (doc.owner_id !== userId && userRoleId !== 1) {
                logger.warn('Document download access denied',{
                    userId:req.user.id,
                    username: req.user.username,
                    documentId: id,
                    ownerId: doc.owner_id,
                    action: 'download'
                });
                return res.status(403).json({ error: 'Access denied'});
            } 

            // Encryption&Decryption
            const filepath = path.join(uploadsDir, doc.filename);
            fs.readFile(filepath, (err, encryptedData) => {
                if (err) {
                    logger.error('Encrypted file read error during download', {
                        error: err.message,
                        filename: doc.filename,
                        userId: req.user.id
                    });
                    return res.status(500).json({ error: 'File read error'});
                }

                try {
                    const decryptedBuffer = decrypt(encryptedData);
                    res.setHeader('Content-Disposition', `attachment; filename ="${doc.title}"`);
                    res.setHeader('Content-Type', 'application/octet-stream');
                    res.send(decryptedBuffer);

                    logger.info('Encrypted document download authorized',{
                        userId:req.user.id,
                        username: req.user.username,
                        documentId: id,
                        title: doc.title,
                        ownerId: doc.owner_id,
                        filename: doc.filename,
                        action: 'download_decrypted'
                    });
                } catch (decryptionErr){
                    logger.error('File decryption failed during download', {
                        error: decryptionErr.message,
                        filename: doc.filename,
                        documentId: id,
                        userId: req.user.id
                    });
                    return res.status(500).json({ error: 'Decryption failed'});
                }
            })

            /*res.download(filepath, doc.title, (err) => {
                logger.info('Document download authorized',{
                    userId:req.user.id,
                    username: req.user.username,
                    documentId: id,
                    ownerId: doc.owner_id,
                    action: 'download'
                });
                if (err) {
                    fs.unlinkSync(filepath);//clean up if download fails
                    res.status(500).json({ error: 'Download failed'});
                }
            });*/
            
        }
    );
});

//DELETE /api/documents/:id - Delete document (owner or admin)
router.delete('/:id', authenticateJWT, (req,res) => {
    const {id} = req.params;
    const userId = req.user.id;
    const userRoleId = req.user.role_id;

    db.get(
        'SELECT filename, title FROM Documents WHERE id = ? AND owner_id = ?',
        [id, userId],
        (err,doc) => {
            if (err) return res.status(500).json({ error: 'Database error'});

            if (!doc && userRoleId != 1) {
                return res.status(403).json({ error: 'Document not found or access denied'});
            }

            //Admin can delete any document
            if (userRoleId === 1) {
                db.get('SELECT filename FROM Documents WHERE id = ?', [id], (err, adminDoc) =>{
                    if (adminDoc) {
                        const filepath = path.join(uploadsDir, adminDoc.filename);
                        fs.unlink(filepath, () => {}); //ignore unlink errors
                    }
                    db.run('DELETE FROM Documents WHERE id = ?', [id], () => {
                        logger.info('Document deleted successfully by admin',{
                            userId:req.user.id,
                            username: req.user.username,
                            documentId: id,
                            title: doc.title,
                            filename: doc.filename,
                            action: 'delete'
                        });
                        res.json({ message: 'Document deleted'});
                    });
                });
            } else {
                //Owner Delete
                const filepath = path.join(uploadsDir, doc.filename);
                fs.unlink(filepath, () => {}); //ignore unlink errors
                db.run('DELETE FROM Documents WHERE id =?', [id], () =>{
                    logger.info('Document deleted successfully',{
                            userId:req.user.id,
                            username: req.user.username,
                            documentId: id,
                            title: doc.title,
                            filename: doc.filename,
                            action: 'delete'
                        });
                    res.json({ message: 'Document deleted'});
                });
            }
        }
    );
});

module.exports = router;