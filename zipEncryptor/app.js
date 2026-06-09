// ============================================================================
// STATE MANAGEMENT
// ============================================================================

const state = {
    currentZip: null,
    currentFiles: new Map(), // filename -> content
    selectedFile: null,
    hasChanges: false,
    zipPassword: null,
    isDecrypted: false
};

const fileTypes = {
    text: ['.txt', '.md', '.log'],
    code: ['.js', '.css', '.html', '.json', '.xml', '.yaml', '.py', '.java'],
    editable: ['.txt', '.md', '.log', '.js', '.css', '.html', '.json', '.xml', '.yaml', '.py', '.java']
};

// ============================================================================
// ENCRYPTION/DECRYPTION UTILITIES
// ============================================================================

const CryptoUtils = {
    // ── Internal helpers ────────────────────────────────────────────────────

    _readAsArrayBuffer(blob) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload  = (e) => resolve(e.target.result);
            reader.onerror = ()  => reject(new Error('Failed to read file'));
            reader.readAsArrayBuffer(blob);
        });
    },

    _readAsText(blob) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload  = (e) => resolve(e.target.result);
            reader.onerror = ()  => reject(new Error('Failed to read file'));
            reader.readAsText(blob);
        });
    },

    // Derive a 256-bit AES key + 128-bit IV from a password using PBKDF2-SHA256.
    // Returns { key: WordArray(256-bit), iv: WordArray(128-bit) }
    _deriveKey(password, salt) {
        const ITERATIONS = 100000;
        const KEY_SIZE   = 256 / 32; // WordArray words for 256-bit key
        const IV_SIZE    = 128 / 32; // WordArray words for 128-bit IV

        // Derive 384 bits total: first 256 = key, last 128 = IV
        const derived = CryptoJS.PBKDF2(password, salt, {
            keySize:    KEY_SIZE + IV_SIZE,
            iterations: ITERATIONS,
            hasher:     CryptoJS.algo.SHA256
        });

        const key = CryptoJS.lib.WordArray.create(derived.words.slice(0, KEY_SIZE));
        const iv  = CryptoJS.lib.WordArray.create(derived.words.slice(KEY_SIZE));
        return { key, iv };
    },

    // ── Public API ──────────────────────────────────────────────────────────

    // Encrypt a ZIP blob with a password.
    //
    // Security properties:
    //   • Key derivation : PBKDF2-SHA256, 100 000 iterations, 128-bit random salt
    //   • Cipher         : AES-256-CBC
    //   • IV             : derived from PBKDF2 (unique per salt)
    //   • Integrity      : none (AES-CBC is encrypt-only; tampered files will
    //                      fail to decrypt or produce corrupt ZIP bytes)
    //
    // Output format (Base64-encoded JSON stored as plain text):
    //   { v: 2, salt: "<hex>", ct: "<base64 ciphertext>" }
    async encryptZip(zipBlob, password) {
        const arrayBuffer = await this._readAsArrayBuffer(zipBlob);
        const uint8       = new Uint8Array(arrayBuffer);

        // Binary → Base64 (chunked to avoid stack overflow on large files)
        const CHUNK  = 8192;
        let binary   = '';
        for (let i = 0; i < uint8.length; i += CHUNK) {
            binary += String.fromCharCode.apply(null, uint8.subarray(i, i + CHUNK));
        }
        const base64Zip = btoa(binary);

        // Fresh 128-bit random salt every encryption
        const salt = CryptoJS.lib.WordArray.random(16);
        const { key, iv } = this._deriveKey(password, salt);

        const encrypted = CryptoJS.AES.encrypt(base64Zip, key, { iv });

        const payload = JSON.stringify({
            v:    2,                            // format version
            salt: salt.toString(),              // hex salt
            ct:   encrypted.ciphertext.toString(CryptoJS.enc.Base64)
        });

        return new Blob([payload], { type: 'text/plain' });
    },

    // Decrypt a blob produced by encryptZip.
    // Returns an ArrayBuffer containing the original ZIP bytes.
    async decryptZip(encryptedBlob, password) {
        const text = await this._readAsText(encryptedBlob);

        let parsed;
        try {
            parsed = JSON.parse(text);
        } catch (e) {
            throw new Error('Invalid file format');
        }

        if (!parsed.v || parsed.v !== 2 || !parsed.salt || !parsed.ct) {
            throw new Error('Invalid or outdated file format');
        }

        const salt = CryptoJS.enc.Hex.parse(parsed.salt);
        const { key, iv } = this._deriveKey(password, salt);

        let decrypted;
        try {
            const cipherParams = CryptoJS.lib.CipherParams.create({
                ciphertext: CryptoJS.enc.Base64.parse(parsed.ct)
            });
            decrypted = CryptoJS.AES.decrypt(cipherParams, key, { iv });
        } catch (e) {
            throw new Error('Wrong password or corrupted file');
        }

        // Guard: CryptoJS returns a WordArray with null/zero sigBytes on wrong password
        if (!decrypted || !decrypted.sigBytes || decrypted.sigBytes <= 0) {
            throw new Error('Wrong password or corrupted file');
        }

        let base64Zip;
        try {
            base64Zip = decrypted.toString(CryptoJS.enc.Utf8);
        } catch (e) {
            throw new Error('Wrong password or corrupted file');
        }

        if (!base64Zip || base64Zip.length === 0) {
            throw new Error('Wrong password or corrupted file');
        }

        let binaryString;
        try {
            binaryString = atob(base64Zip);
        } catch (e) {
            throw new Error('Wrong password or corrupted file');
        }

        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
};

// ============================================================================
// ZIP PROCESSOR MODULE
// ============================================================================

const ZipProcessor = {
    async createZip(files) {
        const zip = new JSZip();

        for (const file of files) {
            if (file.type === 'folder') {
                zip.folder(file.name);
            } else {
                zip.file(file.name, file.data);
            }
        }

        return await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
    },

    async readZip(zipBlob) {
        const zip = new JSZip();
        await zip.loadAsync(zipBlob);
        return zip;
    },

    async extractFiles(zip) {
        const files = new Map();
        const promises = [];

        zip.forEach((relativePath, file) => {
            if (!file.dir) {
                promises.push(
                    file.async('string').then(content => {
                        files.set(relativePath, content);
                    }).catch(() => {
                        // Handle binary files
                        promises.push(
                            file.async('arraybuffer').then(content => {
                                files.set(relativePath, content);
                            })
                        );
                    })
                );
            }
        });

        await Promise.all(promises);
        return files;
    },

    async buildZip(files) {
        const zip = new JSZip();

        for (const [path, content] of files.entries()) {
            zip.file(path, content);
        }

        return await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
    },

    buildTreeStructure(files) {
        const tree = {};

        for (const filePath of files.keys()) {
            const parts = filePath.split('/');
            let current = tree;

            for (let i = 0; i < parts.length; i++) {
                const part = parts[i];
                if (i === parts.length - 1) {
                    current[part] = { type: 'file', path: filePath };
                } else {
                    if (!current[part]) {
                        current[part] = { type: 'folder', children: {} };
                    }
                    current = current[part].children || current[part];
                }
            }
        }

        return tree;
    }
};

// ============================================================================
// UI UTILITIES
// ============================================================================

const UI = {
    showAlert(message, type = 'success', duration = 3000) {
        const alertsContainer = document.getElementById('alerts-container');
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.innerHTML = `
            <span>${message}</span>
            <button class="alert-close">×</button>
        `;

        alert.querySelector('.alert-close').addEventListener('click', () => {
            alert.remove();
        });

        alertsContainer.appendChild(alert);

        if (duration) {
            setTimeout(() => alert.remove(), duration);
        }
    },

    updateStatus(text) {
        document.getElementById('status-text').textContent = text;
    },

    enableTab(tabName) {
        document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });

        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        document.getElementById(`tab-${tabName}`).classList.add('active');
    },

    clearFileList(containerId) {
        const element = document.getElementById(containerId);
        if (element) {
            element.innerHTML = '';
        }
    },

    addFileToList(containerId, name, size = 0, onRemove = null) {
        const fileList = document.getElementById(containerId);
        if (!fileList) {
            console.warn(`File list container not found: ${containerId}`);
            return;
        }
        const item = document.createElement('div');
        item.className = 'file-item';
        item.dataset.filename = name;

        const icon = this.getFileIcon(name);
        const sizeText = size > 0 ? ` (${this.formatFileSize(size)})` : '';

        item.innerHTML = `
            <div class="file-item-name">
                <span class="file-item-icon">${icon}</span>
                <span class="file-item-text">${name}</span>
            </div>
            ${onRemove ? `<button class="file-item-remove">×</button>` : ''}
        `;

        if (onRemove) {
            item.querySelector('.file-item-remove').addEventListener('click', (e) => {
                e.stopPropagation();
                onRemove(name);
                item.remove();
            });
        }

        fileList.appendChild(item);
    },

    getFileIcon(filename) {
        const ext = filename.toLowerCase().split('.').pop();
        const icons = {
            'txt': '📝',
            'md': '📄',
            'js': '⚙️',
            'html': '🌐',
            'css': '🎨',
            'json': '{}',
            'py': '🐍',
            'java': '☕',
            'xml': '📦',
            'yaml': '⚙️',
            'log': '📋',
            'zip': '📦'
        };
        return icons[ext] || '📄';
    },

    formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
    },

    updateEditorStats(content) {
        if (typeof content !== 'string') {
            document.getElementById('status-lines').textContent = 'Lines: —';
            document.getElementById('status-chars').textContent = 'Chars: —';
            document.getElementById('status-size').textContent  = 'Size: —';
            return;
        }
        const lines = content.split('\n').length;
        const chars = content.length;
        const bytes = new Blob([content]).size;
        document.getElementById('status-lines').textContent = `Lines: ${lines}`;
        document.getElementById('status-chars').textContent = `Chars: ${chars}`;
        document.getElementById('status-size').textContent  = `Size: ${this.formatFileSize(bytes)}`;
    },

    getPreviewType(filename) {
        const ext = filename.toLowerCase().split('.').pop();
        if (['.txt', '.md', '.log', '.json', '.xml', '.yaml'].includes('.' + ext)) {
            return 'text';
        } else if (['.js', '.css', '.html', '.py', '.java'].includes('.' + ext)) {
            return 'code';
        } else if (ext === 'html') {
            return 'html';
        }
        return 'text';
    }
};

// ============================================================================
// FILE EXPLORER MODULE
// ============================================================================

const FileExplorer = {
    renderTree(tree, parentElement = null) {
        const container = parentElement || document.getElementById('tree-explorer');
        container.innerHTML = '';

        const renderNode = (node, name, depth = 0) => {
            if (node.type === 'folder') {
                const nodeDiv = document.createElement('div');
                nodeDiv.className = 'tree-node';

                const label = document.createElement('div');
                label.className = 'tree-label';
                label.style.paddingLeft = depth * 20 + 'px';
                label.innerHTML = `
                    <button class="tree-toggle">▶</button>
                    <span class="tree-icon">📁</span>
                    <span>${name}</span>
                `;

                const children = document.createElement('div');
                children.className = 'tree-children';

                const toggle = label.querySelector('.tree-toggle');
                toggle.addEventListener('click', (e) => {
                    e.stopPropagation();
                    children.classList.toggle('open');
                    toggle.textContent = children.classList.contains('open') ? '▼' : '▶';
                });

                nodeDiv.appendChild(label);
                nodeDiv.appendChild(children);

                for (const [childName, childNode] of Object.entries(node.children || {})) {
                    renderNode(childNode, childName, depth + 1);
                }

                if (parentElement === null && depth === 0) {
                    container.appendChild(nodeDiv);
                } else {
                    children.appendChild(nodeDiv);
                }
            } else {
                const nodeDiv = document.createElement('div');
                nodeDiv.className = 'tree-node';

                const label = document.createElement('div');
                label.className = 'tree-label';
                label.style.paddingLeft = depth * 20 + 'px';
                label.innerHTML = `
                    <span style="width: 20px;"></span>
                    <span class="tree-icon">${UI.getFileIcon(name)}</span>
                    <span>${name}</span>
                `;

                label.addEventListener('click', () => {
                    document.querySelectorAll('.tree-label').forEach(l => l.classList.remove('selected'));
                    label.classList.add('selected');
                    FileEditor.loadFile(node.path);
                    // On mobile, close the panel so the editor is visible
                    if (window.innerWidth <= 1024) {
                        document.getElementById('left-panel').classList.remove('mobile-active');
                        document.getElementById('mobile-backdrop').classList.remove('active');
                        document.body.style.overflow = '';
                    }
                });

                nodeDiv.appendChild(label);

                if (parentElement === null && depth === 0) {
                    container.appendChild(nodeDiv);
                } else {
                    // Find parent and add to its children
                    const parent = nodeDiv.parentElement;
                    if (parent) parent.appendChild(nodeDiv);
                }
            }
        };

        for (const [name, node] of Object.entries(tree)) {
            renderNode(node, name);
        }
    }
};

// ============================================================================
// UNSAVED CHANGES DIALOG
// ============================================================================

const UnsavedDialog = {
    _onSave:    null,
    _onDiscard: null,

    show(filename, onSave, onDiscard) {
        this._onSave    = onSave;
        this._onDiscard = onDiscard;
        document.getElementById('unsaved-filename').textContent = filename;
        document.getElementById('unsaved-modal').classList.add('active');
    },

    close() {
        document.getElementById('unsaved-modal').classList.remove('active');
        this._onSave    = null;
        this._onDiscard = null;
    },

    save() {
        const cb = this._onSave;
        this.close();
        if (cb) cb();
    },

    discard() {
        const cb = this._onDiscard;
        this.close();
        if (cb) cb();
    }
};

// ============================================================================
// FILE EDITOR MODULE
// ============================================================================

const FileEditor = {
    loadFile(filePath) {
        const content = state.currentFiles.get(filePath);
        if (content === undefined) {
            UI.showAlert('File not found', 'error');
            return;
        }

        // Guard: warn before discarding unsaved changes
        if (state.hasChanges && state.selectedFile && state.selectedFile !== filePath) {
            UnsavedDialog.show(
                state.selectedFile.split('/').pop(),
                () => {
                    // Save first, then open
                    FileEditor.saveFile();
                    FileEditor._open(filePath);
                },
                () => {
                    // Discard and open
                    state.hasChanges = false;
                    FileEditor._open(filePath);
                }
            );
            return;
        }

        FileEditor._open(filePath);
    },

    _open(filePath) {
        const content = state.currentFiles.get(filePath);                state.selectedFile = filePath;
        state.hasChanges = false;

        // Update filename
        document.getElementById('editor-filename').textContent = filePath.split('/').pop();
        document.getElementById('unsaved-indicator').classList.add('hidden');
        document.getElementById('save-btn').style.display = 'none';
        document.getElementById('export-btn').style.display = 'inline-block';
        document.getElementById('logout-btn').style.display = 'inline-block';

        // Hide all views
        document.getElementById('text-editor-view').classList.add('hidden');
        document.getElementById('preview-editor-view').classList.add('hidden');
        document.getElementById('html-preview-view').classList.add('hidden');
        document.getElementById('empty-state').classList.add('hidden');

        // Binary files (ArrayBuffer) — show a read-only notice, not editable
        const isBinary = content instanceof ArrayBuffer;
        if (isBinary) {
            const codePreview = document.getElementById('code-preview');
            codePreview.innerHTML = '';
            const notice = document.createElement('div');
            notice.style.cssText = 'padding:2rem;color:var(--text-muted);font-size:0.875rem;';
            const ext = filePath.split('.').pop().toUpperCase();
            const kb  = (content.byteLength / 1024).toFixed(1);
            notice.textContent = `Binary file (${ext}, ${kb} KB) — preview not available.`;
            codePreview.appendChild(notice);
            document.getElementById('preview-editor-view').classList.remove('hidden');

            // Update status bar with byte size only
            document.getElementById('status-lines').textContent = 'Lines: —';
            document.getElementById('status-chars').textContent = 'Chars: —';
            document.getElementById('status-size').textContent  = `Size: ${UI.formatFileSize(content.byteLength)}`;
            return;
        }

        // Text content — pick editor view
        const previewType = UI.getPreviewType(filePath);

        if (previewType === 'code') {
            const codePreview = document.getElementById('code-preview');
            codePreview.innerHTML = '';
            const pre  = document.createElement('pre');
            const code = document.createElement('code');
            code.textContent = content;
            code.className   = 'language-' + filePath.split('.').pop();
            pre.appendChild(code);
            codePreview.appendChild(pre);
            try { hljs.highlightElement(code); } catch (e) {}
            document.getElementById('preview-editor-view').classList.remove('hidden');
            UI.updateEditorStats(content);
        } else if (previewType === 'html') {
            const htmlPreview = document.getElementById('html-preview');
            const iframe = document.createElement('iframe');
            iframe.style.cssText = 'width:100%;height:100%;border:none;';
            iframe.setAttribute('sandbox', 'allow-scripts');
            iframe.setAttribute('referrerpolicy', 'no-referrer');
            htmlPreview.innerHTML = '';
            htmlPreview.appendChild(iframe);
            iframe.srcdoc = content;
            document.getElementById('html-preview-view').classList.remove('hidden');
            UI.updateEditorStats(content);
        } else {
            const editor = document.getElementById('text-editor');
            editor.value = content;
            editor.focus();
            UI.updateEditorStats(content);
            document.getElementById('text-editor-view').classList.remove('hidden');
        }
    },

    saveFile() {
        if (!state.selectedFile) return;

        // Don't overwrite binary files
        const existing = state.currentFiles.get(state.selectedFile);
        if (existing instanceof ArrayBuffer) {
            UI.showAlert('Binary files cannot be edited', 'warning');
            return;
        }

        const content = document.getElementById('text-editor').value;
        state.currentFiles.set(state.selectedFile, content);
        state.hasChanges = false;

        document.getElementById('unsaved-indicator').classList.add('hidden');
        document.getElementById('save-btn').style.display = 'none';
        UI.showAlert('File saved', 'success');
    }
};

// ============================================================================
// CREATE ZIP WORKFLOW
// ============================================================================

const createPanel = {
    selectedFiles: new Map(),

    init() {
        const uploadArea = document.getElementById('create-upload-area');
        const fileInput = document.getElementById('create-file-input');
        const createBtn = document.getElementById('create-btn');
        const passwordInput = document.getElementById('create-password');

        ['dragover', 'dragenter'].forEach(event => {
            uploadArea.addEventListener(event, (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(event => {
            uploadArea.addEventListener(event, (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
            });
        });

        uploadArea.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            this.handleFiles(files, true); // true = accumulate files
        });

        uploadArea.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', (e) => {
            this.handleFiles(e.target.files, false); // false = replace files
        });

        createBtn.addEventListener('click', () => this.createZip());
    },

    handleFiles(files, accumulate = false) {
        // If accumulate is false (from file input), clear previous files
        if (!accumulate) {
            UI.clearFileList('create-file-list');
            this.selectedFiles.clear();
        }

        for (const file of files) {
            this.selectedFiles.set(file.name, file);
            UI.addFileToList('create-file-list', file.name, file.size, (name) => {
                this.selectedFiles.delete(name);
                // Update count when file is removed
                UI.updateStatus(`${this.selectedFiles.size} files selected`);
            });
        }

        UI.updateStatus(`${this.selectedFiles.size} files selected`);
    },

    async createZip() {
        if (this.selectedFiles.size === 0) {
            UI.showAlert('Please select files', 'warning');
            return;
        }

        const password = document.getElementById('create-password').value;
        if (!password) {
            UI.showAlert('Please enter a password', 'warning');
            return;
        }

        // Save any open editor content back before building
        if (state.selectedFile && state.currentFiles.has(state.selectedFile)) {
            const editorEl = document.getElementById('text-editor');
            if (!document.getElementById('text-editor-view').classList.contains('hidden')) {
                state.currentFiles.set(state.selectedFile, editorEl.value);
            }
        }

        UI.updateStatus('Compressing...');

        try {
            // Build file list, preferring in-memory content for newly created files
            const files = Array.from(this.selectedFiles.values()).map(f => {
                const inMemory = state.currentFiles.get(f.name);
                if (inMemory !== undefined) {
                    // Use the edited content instead of the original blank File object
                    return { name: f.name, data: new Blob([inMemory], { type: 'text/plain' }), type: 'file' };
                }
                return { name: f.name, data: f, type: 'file' };
            });

            const zipBlob = await ZipProcessor.createZip(files);
            UI.updateStatus('Encrypting (this may take a moment)...');
            const encryptedBlob = await CryptoUtils.encryptZip(zipBlob, password);

            const url = URL.createObjectURL(encryptedBlob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `archive_${new Date().getTime()}.zip`;
            a.click();
            URL.revokeObjectURL(url);

            UI.showAlert('ZIP created and encrypted successfully!', 'success');
            UI.updateStatus('ZIP downloaded');
            this.selectedFiles.clear();
            state.currentFiles.clear();
            state.selectedFile = null;
            UI.clearFileList('create-file-list');
            document.getElementById('create-password').value = '';
            document.getElementById('create-file-input').value = '';
            document.getElementById('export-btn').style.display = 'none';
            document.getElementById('save-btn').style.display = 'none';
            document.getElementById('editor-filename').textContent = 'No file selected';
            document.getElementById('text-editor-view').classList.add('hidden');
            document.getElementById('empty-state').classList.remove('hidden');
        } catch (error) {
            UI.showAlert(`Error: ${error.message}`, 'error');
            UI.updateStatus('Error creating ZIP');
        }
    }
};

// ============================================================================
// IMPORT ZIP WORKFLOW
// ============================================================================

const importPanel = {
    selectedFile: null,

    init() {
        const uploadArea = document.getElementById('import-upload-area');
        const fileInput = document.getElementById('import-file-input');
        const importBtn = document.getElementById('import-btn');

        ['dragover', 'dragenter'].forEach(event => {
            uploadArea.addEventListener(event, (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
        });

        ['dragleave', 'drop'].forEach(event => {
            uploadArea.addEventListener(event, (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
            });
        });

        uploadArea.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.selectedFile = files[0];
                UI.clearFileList('import-file-list');
                UI.addFileToList('import-file-list', files[0].name, files[0].size);
            }
        });

        uploadArea.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.selectedFile = e.target.files[0];
                UI.clearFileList('import-file-list');
                UI.addFileToList('import-file-list', e.target.files[0].name, e.target.files[0].size);
            }
        });

        importBtn.addEventListener('click', () => this.importZip());
    },

    async importZip() {
        if (!this.selectedFile) {
            UI.showAlert('Please select a ZIP file', 'warning');
            return;
        }

        const password = document.getElementById('import-password').value;
        if (!password) {
            UI.showAlert('Please enter a password', 'warning');
            return;
        }

        UI.updateStatus('Decrypting (this may take a moment)...');

        try {
            const arrayBuffer = await CryptoUtils.decryptZip(this.selectedFile, password);
            UI.updateStatus('Reading archive...');
            const zip = await ZipProcessor.readZip(new Blob([arrayBuffer]));
            const files = await ZipProcessor.extractFiles(zip);

            state.currentZip = zip;
            state.currentFiles = files;
            state.zipPassword = password;
            state.isDecrypted = true;

            const tree = ZipProcessor.buildTreeStructure(files);
            FileExplorer.renderTree(tree);

            UI.showAlert('ZIP decrypted successfully!', 'success');
            UI.updateStatus('ZIP loaded');
            UI.enableTab('explorer');
            document.getElementById('logout-btn').style.display = 'inline-block';

            // On mobile, slide the panel open so the user sees the file tree
            if (window.innerWidth <= 1024) {
                const leftPanel = document.getElementById('left-panel');
                const backdrop  = document.getElementById('mobile-backdrop');
                leftPanel.classList.add('mobile-active');
                backdrop.classList.add('active');
                document.body.style.overflow = 'hidden';
            }

            // Clear import form
            document.getElementById('import-password').value = '';
            document.getElementById('import-file-input').value = '';
        } catch (error) {
            UI.showAlert(`Error: ${error.message}`, 'error');
            UI.updateStatus('Error importing ZIP');
        }
    }
};

// ============================================================================
// NEW FILE MODULE
// ============================================================================

const NewFileManager = {
    // Who triggered the modal: 'create' (Create tab) or 'explorer' (Explorer tab)
    _origin: null,

    open(origin) {
        this._origin = origin;
        const modal = document.getElementById('new-file-modal');
        const input = document.getElementById('new-file-name');
        input.value = '';
        modal.classList.add('active');
        // Focus after the transition frame
        requestAnimationFrame(() => input.focus());
    },

    close() {
        document.getElementById('new-file-modal').classList.remove('active');
        this._origin = null;
    },

    confirm() {
        const raw = document.getElementById('new-file-name').value.trim();
        if (!raw) {
            UI.showAlert('Please enter a filename', 'warning');
            return;
        }
        // Sanitise: no slashes or backslashes (root-only requirement)
        const filename = raw.replace(/[/\\]/g, '_');

        if (this._origin === 'explorer') {
            this._addToExplorer(filename);
        } else {
            this._addToCreate(filename);
        }
        this.close();
    },

    // Add new empty file into an already-open ZIP (Explorer context)
    _addToExplorer(filename) {
        if (state.currentFiles.has(filename)) {
            UI.showAlert(`"${filename}" already exists`, 'warning');
            return;
        }
        state.currentFiles.set(filename, '');

        // Rebuild the tree so the new file appears
        const tree = ZipProcessor.buildTreeStructure(state.currentFiles);
        FileExplorer.renderTree(tree);

        // Open the new file immediately in the editor
        FileEditor.loadFile(filename);

        // Make sure Export button is visible
        document.getElementById('export-btn').style.display = 'inline-block';

        UI.showAlert(`"${filename}" created`, 'success');
        UI.updateStatus('New file created');
    },

    // Add new empty file to the Create tab's pending file list
    _addToCreate(filename) {
        // We need a File-like object; create a Blob and attach a name
        const blob = new Blob([''], { type: 'text/plain' });
        const file = new File([blob], filename, { type: 'text/plain' });

        createPanel.selectedFiles.set(filename, file);
        UI.addFileToList('create-file-list', filename, 0, (name) => {
            createPanel.selectedFiles.delete(name);
            UI.updateStatus(`${createPanel.selectedFiles.size} files selected`);
        });

        // Also open it in the editor so the user can write content right away.
        // We store it in a temporary in-memory map keyed by name.
        state.currentFiles.set(filename, '');
        state.zipPassword = state.zipPassword || null;
        FileEditor.loadFile(filename);

        // Show Export button so user can ZIP even without importing first
        document.getElementById('export-btn').style.display = 'inline-block';

        UI.showAlert(`"${filename}" created — write content then Create ZIP`, 'success');
        UI.updateStatus('New file ready to edit');
    }
};

// ============================================================================
// PASSWORD PROMPT HELPER
// ============================================================================

const PasswordPrompt = {
    _callback: null,

    request(title, callback) {
        this._callback = callback;
        document.querySelector('#password-modal .modal-title').textContent = title;
        document.getElementById('modal-password').value = '';
        document.getElementById('password-modal').classList.add('active');
        requestAnimationFrame(() => document.getElementById('modal-password').focus());
    },

    confirm() {
        const password = document.getElementById('modal-password').value;
        if (!password) {
            UI.showAlert('Please enter a password', 'warning');
            return;
        }
        document.getElementById('password-modal').classList.remove('active');
        if (this._callback) {
            this._callback(password);
            this._callback = null;
        }
    },

    cancel() {
        document.getElementById('password-modal').classList.remove('active');
        this._callback = null;
    }
};

// ============================================================================
// EVENT LISTENERS
// ============================================================================

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        const tabName = tab.dataset.tab;
        UI.enableTab(tabName);
    });
});

// New file — Create tab
document.getElementById('create-new-file-btn').addEventListener('click', () => {
    NewFileManager.open('create');
});

// New file — Explorer tab
document.getElementById('explorer-new-file-btn').addEventListener('click', () => {
    NewFileManager.open('explorer');
});

// New file modal buttons
document.getElementById('new-file-confirm').addEventListener('click', () => NewFileManager.confirm());
document.getElementById('new-file-cancel').addEventListener('click',  () => NewFileManager.close());
document.getElementById('new-file-name').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') NewFileManager.confirm();
    if (e.key === 'Escape') NewFileManager.close();
});

// Text editor changes
document.getElementById('text-editor').addEventListener('input', (e) => {
    if (state.selectedFile) {
        state.hasChanges = true;
        document.getElementById('unsaved-indicator').classList.remove('hidden');
        document.getElementById('save-btn').style.display = 'inline-block';
        UI.updateEditorStats(e.target.value);
    }
});

// Save file
document.getElementById('save-btn').addEventListener('click', () => {
    FileEditor.saveFile();
});

// Export ZIP
document.getElementById('export-btn').addEventListener('click', async () => {
    if (state.currentFiles.size === 0) {
        UI.showAlert('Nothing to export', 'warning');
        return;
    }

    // Flush any unsaved editor content first
    if (state.selectedFile) {
        const editorView = document.getElementById('text-editor-view');
        if (!editorView.classList.contains('hidden')) {
            FileEditor.saveFile();
        }
    }

    // If no password yet (files created from scratch), ask for one now
    if (!state.zipPassword) {
        PasswordPrompt.request('Set a password for this archive', (password) => {
            state.zipPassword = password;
            exportZip();
        });
        return;
    }

    exportZip();
});

async function exportZip() {
    UI.updateStatus('Compressing...');
    try {
        const zipBlob = await ZipProcessor.buildZip(state.currentFiles);
        UI.updateStatus('Encrypting (this may take a moment)...');
        const encryptedBlob = await CryptoUtils.encryptZip(zipBlob, state.zipPassword);

        const url = URL.createObjectURL(encryptedBlob);
        const a   = document.createElement('a');
        a.href    = url;
        a.download = `archive_${Date.now()}.zip`;
        a.click();
        URL.revokeObjectURL(url);

        UI.showAlert('ZIP exported successfully!', 'success');
        UI.updateStatus('ZIP exported');
    } catch (error) {
        UI.showAlert(`Error: ${error.message}`, 'error');
        UI.updateStatus('Error exporting ZIP');
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    createPanel.init();
    importPanel.init();

    // ── Unsaved changes dialog ───────────────────────────────────────────
    document.getElementById('unsaved-save').addEventListener('click',    () => UnsavedDialog.save());
    document.getElementById('unsaved-discard').addEventListener('click', () => UnsavedDialog.discard());
    document.getElementById('unsaved-cancel').addEventListener('click',  () => UnsavedDialog.close());

    // ── Password modal ───────────────────────────────────────────────────
    document.getElementById('modal-submit').addEventListener('click', () => PasswordPrompt.confirm());
    document.getElementById('modal-cancel').addEventListener('click', () => PasswordPrompt.cancel());
    document.getElementById('modal-password').addEventListener('keydown', (e) => {
        if (e.key === 'Enter')  PasswordPrompt.confirm();
        if (e.key === 'Escape') PasswordPrompt.cancel();
    });

    // ── Mobile panel open/close ──────────────────────────────────────────
    const leftPanel   = document.getElementById('left-panel');
    const backdrop    = document.getElementById('mobile-backdrop');
    const menuBtn     = document.getElementById('mobile-menu-btn');
    const closeBtn    = document.getElementById('panel-close-btn');

    function openPanel() {
        leftPanel.classList.add('mobile-active');
        backdrop.classList.add('active');
        document.body.style.overflow = 'hidden';
    }

    function closePanel() {
        leftPanel.classList.remove('mobile-active');
        backdrop.classList.remove('active');
        document.body.style.overflow = '';
    }

    menuBtn.addEventListener('click', openPanel);
    closeBtn.addEventListener('click', closePanel);
    backdrop.addEventListener('click', closePanel);

    UI.updateStatus('Ready');

    // ── Logout / Lock ────────────────────────────────────────────────────
    document.getElementById('logout-btn').addEventListener('click', () => {
        // Wipe all sensitive state
        state.currentZip     = null;
        state.currentFiles   = new Map();
        state.selectedFile   = null;
        state.hasChanges     = false;
        state.zipPassword    = null;
        state.isDecrypted    = false;

        // Reset left panel
        UI.clearFileList('create-file-list');
        UI.clearFileList('import-file-list');
        document.getElementById('tree-explorer').innerHTML = '';
        document.getElementById('create-password').value   = '';
        document.getElementById('import-password').value   = '';
        document.getElementById('create-file-input').value = '';
        document.getElementById('import-file-input').value = '';
        createPanel.selectedFiles.clear();
        importPanel.selectedFile = null;

        // Reset right panel
        document.getElementById('editor-filename').textContent = 'No file selected';
        document.getElementById('text-editor').value           = '';
        document.getElementById('unsaved-indicator').classList.add('hidden');
        document.getElementById('save-btn').style.display      = 'none';
        document.getElementById('export-btn').style.display    = 'none';
        document.getElementById('text-editor-view').classList.add('hidden');
        document.getElementById('preview-editor-view').classList.add('hidden');
        document.getElementById('html-preview-view').classList.add('hidden');
        document.getElementById('empty-state').classList.remove('hidden');
        document.getElementById('status-lines').textContent    = 'Lines: 0';
        document.getElementById('status-chars').textContent    = 'Chars: 0';
        document.getElementById('status-size').textContent     = 'Size: 0 B';

        // Hide lock button, switch to Create tab
        document.getElementById('logout-btn').style.display = 'none';
        UI.enableTab('create');
        UI.updateStatus('Locked — all data cleared');

        // Close mobile panel if open
        document.getElementById('left-panel').classList.remove('mobile-active');
        document.getElementById('mobile-backdrop').classList.remove('active');
        document.body.style.overflow = '';
    });
});
