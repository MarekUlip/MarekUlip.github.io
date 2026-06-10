// ============================================================================
// STATE MANAGEMENT
// ============================================================================

const state = {
    currentFiles: new Map(), // path -> string | ArrayBuffer
    selectedFile: null,
    hasChanges: false,
    zipPassword: null,
};

// ============================================================================
// ZIP PROCESSOR  (zip.js — produces real AES-256 encrypted ZIPs)
// ============================================================================

const ZipProcessor = {

    // Create an encrypted ZIP blob from a Map<filename, content>
    async createZip(filesMap, password) {
        const { BlobWriter, BlobReader, TextReader, Uint8ArrayReader, ZipWriter } = zipjs;

        const zipBlobWriter = new BlobWriter('application/zip');
        const writer = new ZipWriter(zipBlobWriter, {
            password,
            encryptionStrength: 3,   // AES-256
            zipCrypto: false,        // use WinZip AES, not legacy ZipCrypto
        });

        for (const [name, content] of filesMap.entries()) {
            let reader;
            if (content instanceof ArrayBuffer) {
                reader = new Uint8ArrayReader(new Uint8Array(content));
            } else {
                reader = new TextReader(content);
            }
            await writer.add(name, reader);
        }

        await writer.close();
        return zipBlobWriter.getData();
    },

    // Open an encrypted ZIP blob; returns Map<path, string|ArrayBuffer>
    async readZip(blob, password) {
        const { BlobReader, ZipReader, TextWriter, Uint8ArrayWriter } = zipjs;

        const reader = new ZipReader(new BlobReader(blob), { password });
        const entries = await reader.getEntries();
        await reader.close();
        return entries;
    },

    // Extract text / binary content from zip.js entries
    async extractFiles(entries) {
        const { TextWriter, Uint8ArrayWriter } = zipjs;
        const files = new Map();

        for (const entry of entries) {
            if (entry.directory) continue;
            try {
                const text = await entry.getData(new TextWriter());
                files.set(entry.filename, text);
            } catch {
                try {
                    const buf = await entry.getData(new Uint8ArrayWriter());
                    files.set(entry.filename, buf.buffer);
                } catch {
                    // skip unreadable entries
                }
            }
        }
        return files;
    },

    buildTreeStructure(files) {
        const tree = {};
        for (const filePath of files.keys()) {
            const parts = filePath.split('/');
            let current = tree;
            for (let i = 0; i < parts.length; i++) {
                const part = parts[i];
                if (!part) continue;
                if (i === parts.length - 1) {
                    current[part] = { type: 'file', path: filePath };
                } else {
                    if (!current[part]) current[part] = { type: 'folder', children: {} };
                    current = current[part].children;
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
        const container = document.getElementById('alerts-container');
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.innerHTML = `<span>${message}</span><button class="alert-close">×</button>`;
        alert.querySelector('.alert-close').addEventListener('click', () => alert.remove());
        container.appendChild(alert);
        if (duration) setTimeout(() => alert.remove(), duration);
    },

    updateStatus(text) {
        document.getElementById('status-text').textContent = text;
    },

    enableTab(tabName) {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        document.getElementById(`tab-${tabName}`).classList.add('active');
    },

    clearFileList(containerId) {
        const el = document.getElementById(containerId);
        if (el) el.innerHTML = '';
    },

    addFileToList(containerId, name, size = 0, onRemove = null) {
        const list = document.getElementById(containerId);
        if (!list) return;
        const item = document.createElement('div');
        item.className = 'file-item';
        item.dataset.filename = name;
        item.innerHTML = `
            <div class="file-item-name">
                <span class="file-item-icon">${this.getFileIcon(name)}</span>
                <span class="file-item-text">${name}</span>
            </div>
            ${onRemove ? '<button class="file-item-remove">×</button>' : ''}
        `;
        if (onRemove) {
            item.querySelector('.file-item-remove').addEventListener('click', e => {
                e.stopPropagation();
                onRemove(name);
                item.remove();
            });
        }
        list.appendChild(item);
    },

    getFileIcon(filename) {
        const ext = (filename.split('.').pop() || '').toLowerCase();
        const icons = { txt:'📝', md:'📄', js:'⚙️', html:'🌐', css:'🎨',
                        json:'{}', py:'🐍', java:'☕', xml:'📦', yaml:'⚙️', log:'📋', zip:'📦' };
        return icons[ext] || '📄';
    },

    formatFileSize(bytes) {
        if (!bytes) return '0 B';
        const k = 1024, sizes = ['B','KB','MB','GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    },

    updateEditorStats(content) {
        if (typeof content !== 'string') {
            document.getElementById('status-lines').textContent = 'Lines: —';
            document.getElementById('status-chars').textContent = 'Chars: —';
            document.getElementById('status-size').textContent  = 'Size: —';
            return;
        }
        document.getElementById('status-lines').textContent = `Lines: ${content.split('\n').length}`;
        document.getElementById('status-chars').textContent = `Chars: ${content.length}`;
        document.getElementById('status-size').textContent  = `Size: ${this.formatFileSize(new Blob([content]).size)}`;
    },

    getPreviewType(filename) {
        const ext = (filename.split('.').pop() || '').toLowerCase();
        if (['txt','md','log','json','xml','yaml'].includes(ext)) return 'text';
        if (['js','css','py','java'].includes(ext)) return 'code';
        if (ext === 'html') return 'html';
        return 'text';
    }
};

// ============================================================================
// FILE EXPLORER
// ============================================================================

const FileExplorer = {
    renderTree(tree) {
        const container = document.getElementById('tree-explorer');
        container.innerHTML = '';

        const renderNode = (node, name, parentEl, depth) => {
            const div = document.createElement('div');
            div.className = 'tree-node';

            if (node.type === 'folder') {
                const label = document.createElement('div');
                label.className = 'tree-label';
                label.style.paddingLeft = depth * 20 + 'px';
                label.innerHTML = `<button class="tree-toggle">▶</button>
                    <span class="tree-icon">📁</span><span>${name}</span>`;

                const children = document.createElement('div');
                children.className = 'tree-children';

                label.querySelector('.tree-toggle').addEventListener('click', e => {
                    e.stopPropagation();
                    children.classList.toggle('open');
                    e.target.textContent = children.classList.contains('open') ? '▼' : '▶';
                });

                div.appendChild(label);
                div.appendChild(children);

                for (const [childName, childNode] of Object.entries(node.children || {})) {
                    renderNode(childNode, childName, children, depth + 1);
                }
            } else {
                const label = document.createElement('div');
                label.className = 'tree-label';
                label.style.paddingLeft = depth * 20 + 'px';
                label.innerHTML = `<span style="width:20px"></span>
                    <span class="tree-icon">${UI.getFileIcon(name)}</span><span>${name}</span>`;

                label.addEventListener('click', () => {
                    document.querySelectorAll('.tree-label').forEach(l => l.classList.remove('selected'));
                    label.classList.add('selected');
                    FileEditor.loadFile(node.path);
                    if (window.innerWidth <= 1024) {
                        document.getElementById('left-panel').classList.remove('mobile-active');
                        document.getElementById('mobile-backdrop').classList.remove('active');
                        document.body.style.overflow = '';
                    }
                });

                div.appendChild(label);
            }

            parentEl.appendChild(div);
        };

        for (const [name, node] of Object.entries(tree)) {
            renderNode(node, name, container, 0);
        }
    }
};

// ============================================================================
// UNSAVED CHANGES DIALOG
// ============================================================================

const UnsavedDialog = {
    _onSave: null, _onDiscard: null,

    show(filename, onSave, onDiscard) {
        this._onSave = onSave;
        this._onDiscard = onDiscard;
        document.getElementById('unsaved-filename').textContent = filename;
        document.getElementById('unsaved-modal').classList.add('active');
    },
    close() {
        document.getElementById('unsaved-modal').classList.remove('active');
        this._onSave = this._onDiscard = null;
    },
    save()    { const cb = this._onSave;    this.close(); if (cb) cb(); },
    discard() { const cb = this._onDiscard; this.close(); if (cb) cb(); }
};

// ============================================================================
// FILE EDITOR
// ============================================================================

const FileEditor = {
    loadFile(filePath) {
        const content = state.currentFiles.get(filePath);
        if (content === undefined) { UI.showAlert('File not found', 'error'); return; }

        if (state.hasChanges && state.selectedFile && state.selectedFile !== filePath) {
            UnsavedDialog.show(state.selectedFile.split('/').pop(),
                () => { FileEditor.saveFile(); FileEditor._open(filePath); },
                () => { state.hasChanges = false; FileEditor._open(filePath); }
            );
            return;
        }
        FileEditor._open(filePath);
    },

    _open(filePath) {
        const content = state.currentFiles.get(filePath);
        state.selectedFile = filePath;
        state.hasChanges = false;

        document.getElementById('editor-filename').textContent = filePath.split('/').pop();
        document.getElementById('unsaved-indicator').classList.add('hidden');
        document.getElementById('save-btn').style.display = 'none';
        document.getElementById('export-btn').style.display = 'inline-block';
        document.getElementById('logout-btn').style.display = 'inline-block';

        ['text-editor-view','preview-editor-view','html-preview-view','empty-state']
            .forEach(id => document.getElementById(id).classList.add('hidden'));

        if (content instanceof ArrayBuffer) {
            const preview = document.getElementById('code-preview');
            preview.innerHTML = '';
            const notice = document.createElement('div');
            notice.style.cssText = 'padding:2rem;color:var(--text-muted);font-size:0.875rem;';
            notice.textContent = `Binary file (${filePath.split('.').pop().toUpperCase()}, ${UI.formatFileSize(content.byteLength)}) — preview not available.`;
            preview.appendChild(notice);
            document.getElementById('preview-editor-view').classList.remove('hidden');
            document.getElementById('status-lines').textContent = 'Lines: —';
            document.getElementById('status-chars').textContent = 'Chars: —';
            document.getElementById('status-size').textContent  = `Size: ${UI.formatFileSize(content.byteLength)}`;
            return;
        }

        const type = UI.getPreviewType(filePath);
        if (type === 'code') {
            const preview = document.getElementById('code-preview');
            preview.innerHTML = '';
            const pre = document.createElement('pre');
            const code = document.createElement('code');
            code.textContent = content;
            code.className = 'language-' + filePath.split('.').pop();
            pre.appendChild(code);
            preview.appendChild(pre);
            try { hljs.highlightElement(code); } catch {}
            document.getElementById('preview-editor-view').classList.remove('hidden');
            UI.updateEditorStats(content);
        } else if (type === 'html') {
            const htmlPreview = document.getElementById('html-preview');
            htmlPreview.innerHTML = '';
            const iframe = document.createElement('iframe');
            iframe.style.cssText = 'width:100%;height:100%;border:none;';
            iframe.setAttribute('sandbox', 'allow-scripts');
            iframe.setAttribute('referrerpolicy', 'no-referrer');
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
        const existing = state.currentFiles.get(state.selectedFile);
        if (existing instanceof ArrayBuffer) { UI.showAlert('Binary files cannot be edited', 'warning'); return; }
        const content = document.getElementById('text-editor').value;
        state.currentFiles.set(state.selectedFile, content);
        state.hasChanges = false;
        document.getElementById('unsaved-indicator').classList.add('hidden');
        document.getElementById('save-btn').style.display = 'none';
        UI.showAlert('File saved', 'success');
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
        const pw = document.getElementById('modal-password').value;
        if (!pw) { UI.showAlert('Please enter a password', 'warning'); return; }
        document.getElementById('password-modal').classList.remove('active');
        if (this._callback) { this._callback(pw); this._callback = null; }
    },

    cancel() {
        document.getElementById('password-modal').classList.remove('active');
        this._callback = null;
    }
};

// ============================================================================
// NEW FILE MODULE
// ============================================================================

const NewFileManager = {
    _origin: null,

    open(origin) {
        this._origin = origin;
        const input = document.getElementById('new-file-name');
        input.value = '';
        document.getElementById('new-file-modal').classList.add('active');
        requestAnimationFrame(() => input.focus());
    },

    close() {
        document.getElementById('new-file-modal').classList.remove('active');
        this._origin = null;
    },

    confirm() {
        const raw = document.getElementById('new-file-name').value.trim();
        if (!raw) { UI.showAlert('Please enter a filename', 'warning'); return; }
        const filename = raw.replace(/[/\\]/g, '_');
        if (this._origin === 'explorer') this._addToExplorer(filename);
        else                             this._addToCreate(filename);
        this.close();
    },

    _addToExplorer(filename) {
        if (state.currentFiles.has(filename)) { UI.showAlert(`"${filename}" already exists`, 'warning'); return; }
        state.currentFiles.set(filename, '');
        FileExplorer.renderTree(ZipProcessor.buildTreeStructure(state.currentFiles));
        FileEditor.loadFile(filename);
        document.getElementById('export-btn').style.display = 'inline-block';
        UI.showAlert(`"${filename}" created`, 'success');
        UI.updateStatus('New file created');
    },

    _addToCreate(filename) {
        const file = new File([''], filename, { type: 'text/plain' });
        createPanel.selectedFiles.set(filename, file);
        UI.addFileToList('create-file-list', filename, 0, name => {
            createPanel.selectedFiles.delete(name);
            state.currentFiles.delete(name);
            UI.updateStatus(`${createPanel.selectedFiles.size} files selected`);
        });
        state.currentFiles.set(filename, '');
        FileEditor.loadFile(filename);
        document.getElementById('export-btn').style.display = 'inline-block';
        UI.showAlert(`"${filename}" created — write content then Create ZIP`, 'success');
        UI.updateStatus('New file ready to edit');
    }
};

// ============================================================================
// CREATE ZIP WORKFLOW
// ============================================================================

const createPanel = {
    selectedFiles: new Map(),

    init() {
        const uploadArea = document.getElementById('create-upload-area');
        const fileInput  = document.getElementById('create-file-input');

        ['dragover','dragenter'].forEach(ev =>
            uploadArea.addEventListener(ev, e => { e.preventDefault(); uploadArea.classList.add('dragover'); }));
        ['dragleave','drop'].forEach(ev =>
            uploadArea.addEventListener(ev, e => { e.preventDefault(); uploadArea.classList.remove('dragover'); }));

        uploadArea.addEventListener('drop', e => this.handleFiles(e.dataTransfer.files, true));
        uploadArea.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', e => this.handleFiles(e.target.files, false));
        document.getElementById('create-btn').addEventListener('click', () => this.createZip());
    },

    handleFiles(files, accumulate = false) {
        if (!accumulate) { UI.clearFileList('create-file-list'); this.selectedFiles.clear(); }
        for (const file of files) {
            this.selectedFiles.set(file.name, file);
            UI.addFileToList('create-file-list', file.name, file.size, name => {
                this.selectedFiles.delete(name);
                UI.updateStatus(`${this.selectedFiles.size} files selected`);
            });
        }
        UI.updateStatus(`${this.selectedFiles.size} files selected`);
    },

    async createZip() {
        if (this.selectedFiles.size === 0) { UI.showAlert('Please select files', 'warning'); return; }
        const password = document.getElementById('create-password').value;
        if (!password) { UI.showAlert('Please enter a password', 'warning'); return; }

        // Flush open editor content
        if (state.selectedFile) {
            const view = document.getElementById('text-editor-view');
            if (!view.classList.contains('hidden'))
                state.currentFiles.set(state.selectedFile, document.getElementById('text-editor').value);
        }

        UI.updateStatus('Building ZIP...');
        try {
            // Build the files map — prefer in-memory edits for newly created files
            const filesMap = new Map();
            for (const [name, file] of this.selectedFiles.entries()) {
                const inMemory = state.currentFiles.get(name);
                if (inMemory !== undefined) {
                    filesMap.set(name, inMemory);
                } else {
                    filesMap.set(name, await file.arrayBuffer());
                }
            }

            UI.updateStatus('Encrypting...');
            const zipBlob = await ZipProcessor.createZip(filesMap, password);
            const url = URL.createObjectURL(zipBlob);
            const a = document.createElement('a');
            a.href = url; a.download = `archive_${Date.now()}.zip`; a.click();
            URL.revokeObjectURL(url);

            UI.showAlert('Encrypted ZIP created!', 'success');
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
        } catch (err) {
            UI.showAlert(`Error: ${err.message}`, 'error');
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
        const fileInput  = document.getElementById('import-file-input');

        ['dragover','dragenter'].forEach(ev =>
            uploadArea.addEventListener(ev, e => { e.preventDefault(); uploadArea.classList.add('dragover'); }));
        ['dragleave','drop'].forEach(ev =>
            uploadArea.addEventListener(ev, e => { e.preventDefault(); uploadArea.classList.remove('dragover'); }));

        uploadArea.addEventListener('drop', e => {
            if (e.dataTransfer.files.length) {
                this.selectedFile = e.dataTransfer.files[0];
                UI.clearFileList('import-file-list');
                UI.addFileToList('import-file-list', this.selectedFile.name, this.selectedFile.size);
            }
        });
        uploadArea.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', e => {
            if (e.target.files.length) {
                this.selectedFile = e.target.files[0];
                UI.clearFileList('import-file-list');
                UI.addFileToList('import-file-list', this.selectedFile.name, this.selectedFile.size);
            }
        });
        document.getElementById('import-btn').addEventListener('click', () => this.importZip());
    },

    async importZip() {
        if (!this.selectedFile) { UI.showAlert('Please select a ZIP file', 'warning'); return; }
        const password = document.getElementById('import-password').value;
        if (!password) { UI.showAlert('Please enter a password', 'warning'); return; }

        UI.updateStatus('Decrypting...');
        try {
            const entries = await ZipProcessor.readZip(this.selectedFile, password);
            UI.updateStatus('Reading files...');
            const files = await ZipProcessor.extractFiles(entries);

            state.currentFiles = files;
            state.zipPassword  = password;

            FileExplorer.renderTree(ZipProcessor.buildTreeStructure(files));

            UI.showAlert('ZIP decrypted successfully!', 'success');
            UI.updateStatus('ZIP loaded');
            UI.enableTab('explorer');
            document.getElementById('logout-btn').style.display = 'inline-block';

            if (window.innerWidth <= 1024) {
                document.getElementById('left-panel').classList.add('mobile-active');
                document.getElementById('mobile-backdrop').classList.add('active');
                document.body.style.overflow = 'hidden';
            }

            document.getElementById('import-password').value = '';
            document.getElementById('import-file-input').value = '';
            this.selectedFile = null;
            UI.clearFileList('import-file-list');
        } catch (err) {
            const msg = err.message || '';
            if (msg.toLowerCase().includes('password') || msg.toLowerCase().includes('invalid'))
                UI.showAlert('Wrong password or invalid ZIP file', 'error');
            else
                UI.showAlert(`Error: ${msg}`, 'error');
            UI.updateStatus('Error importing ZIP');
        }
    }
};

// ============================================================================
// EXPORT ZIP
// ============================================================================

async function exportZip() {
    // Flush open editor
    if (state.selectedFile) {
        const view = document.getElementById('text-editor-view');
        if (!view.classList.contains('hidden'))
            FileEditor.saveFile();
    }

    UI.updateStatus('Building ZIP...');
    try {
        UI.updateStatus('Encrypting...');
        const zipBlob = await ZipProcessor.createZip(state.currentFiles, state.zipPassword);
        const url = URL.createObjectURL(zipBlob);
        const a = document.createElement('a');
        a.href = url; a.download = `archive_${Date.now()}.zip`; a.click();
        URL.revokeObjectURL(url);
        UI.showAlert('ZIP exported!', 'success');
        UI.updateStatus('ZIP exported');
    } catch (err) {
        UI.showAlert(`Error: ${err.message}`, 'error');
        UI.updateStatus('Error exporting');
    }
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => UI.enableTab(tab.dataset.tab));
});

// New file buttons
document.getElementById('create-new-file-btn').addEventListener('click', () => NewFileManager.open('create'));
document.getElementById('explorer-new-file-btn').addEventListener('click', () => NewFileManager.open('explorer'));

// New file modal
document.getElementById('new-file-confirm').addEventListener('click', () => NewFileManager.confirm());
document.getElementById('new-file-cancel').addEventListener('click',  () => NewFileManager.close());
document.getElementById('new-file-name').addEventListener('keydown', e => {
    if (e.key === 'Enter') NewFileManager.confirm();
    if (e.key === 'Escape') NewFileManager.close();
});

// Unsaved changes dialog
document.getElementById('unsaved-save').addEventListener('click',    () => UnsavedDialog.save());
document.getElementById('unsaved-discard').addEventListener('click', () => UnsavedDialog.discard());
document.getElementById('unsaved-cancel').addEventListener('click',  () => UnsavedDialog.close());

// Text editor changes
document.getElementById('text-editor').addEventListener('input', e => {
    if (state.selectedFile) {
        state.hasChanges = true;
        document.getElementById('unsaved-indicator').classList.remove('hidden');
        document.getElementById('save-btn').style.display = 'inline-block';
        UI.updateEditorStats(e.target.value);
    }
});

// Save
document.getElementById('save-btn').addEventListener('click', () => FileEditor.saveFile());

// Export
document.getElementById('export-btn').addEventListener('click', () => {
    if (state.currentFiles.size === 0) { UI.showAlert('Nothing to export', 'warning'); return; }
    if (!state.zipPassword) {
        PasswordPrompt.request('Set a password for this archive', pw => {
            state.zipPassword = pw;
            exportZip();
        });
        return;
    }
    exportZip();
});

// Password modal
document.getElementById('modal-submit').addEventListener('click', () => PasswordPrompt.confirm());
document.getElementById('modal-cancel').addEventListener('click',  () => PasswordPrompt.cancel());
document.getElementById('modal-password').addEventListener('keydown', e => {
    if (e.key === 'Enter')  PasswordPrompt.confirm();
    if (e.key === 'Escape') PasswordPrompt.cancel();
});

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    createPanel.init();
    importPanel.init();

    // Mobile panel
    const leftPanel = document.getElementById('left-panel');
    const backdrop  = document.getElementById('mobile-backdrop');
    const menuBtn   = document.getElementById('mobile-menu-btn');
    const closeBtn  = document.getElementById('panel-close-btn');

    const openPanel  = () => { leftPanel.classList.add('mobile-active'); backdrop.classList.add('active'); document.body.style.overflow = 'hidden'; };
    const closePanel = () => { leftPanel.classList.remove('mobile-active'); backdrop.classList.remove('active'); document.body.style.overflow = ''; };

    menuBtn.addEventListener('click', openPanel);
    closeBtn.addEventListener('click', closePanel);
    backdrop.addEventListener('click', closePanel);

    // Logout / Lock
    document.getElementById('logout-btn').addEventListener('click', () => {
        state.currentFiles   = new Map();
        state.selectedFile   = null;
        state.hasChanges     = false;
        state.zipPassword    = null;

        UI.clearFileList('create-file-list');
        UI.clearFileList('import-file-list');
        document.getElementById('tree-explorer').innerHTML  = '';
        document.getElementById('create-password').value    = '';
        document.getElementById('import-password').value    = '';
        document.getElementById('create-file-input').value  = '';
        document.getElementById('import-file-input').value  = '';
        createPanel.selectedFiles.clear();
        importPanel.selectedFile = null;

        document.getElementById('editor-filename').textContent = 'No file selected';
        document.getElementById('text-editor').value           = '';
        document.getElementById('unsaved-indicator').classList.add('hidden');
        document.getElementById('save-btn').style.display      = 'none';
        document.getElementById('export-btn').style.display    = 'none';
        document.getElementById('logout-btn').style.display    = 'none';
        ['text-editor-view','preview-editor-view','html-preview-view'].forEach(id =>
            document.getElementById(id).classList.add('hidden'));
        document.getElementById('empty-state').classList.remove('hidden');
        document.getElementById('status-lines').textContent = 'Lines: 0';
        document.getElementById('status-chars').textContent = 'Chars: 0';
        document.getElementById('status-size').textContent  = 'Size: 0 B';

        UI.enableTab('create');
        closePanel();
        UI.updateStatus('Locked — all data cleared');
    });

    UI.updateStatus('Ready');
});
