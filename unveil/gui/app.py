"""Tk desktop workbench. Target execution is delegated only to exported launchers."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from .model import Patch, Project, import_patches, parse_rva
from .package import export_package, open_sandbox, suggested_destination
from .search import BinaryView, Hit
from unveil.core.model import InputArtifact


class Workbench:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.project: Project | None = None
        self.artifact: InputArtifact | None = None
        self.view: BinaryView | None = None
        self.hit_view: BinaryView | None = None
        self.hits: list[Hit] = []
        self.package: Path | None = None
        self.edit_index: int | None = None
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='unveil-gui')
        self.pending = None
        self.callback = None
        self.closed = False
        root.title('Unveil — Patch Workbench')
        root.geometry('1180x820')
        root.minsize(980, 720)
        root.configure(bg='#10151f')
        root.protocol('WM_DELETE_WINDOW', self.close)
        self._style()
        self.title = tk.StringVar(value='Application')
        self.status = tk.StringVar(value='Pronto · Nenhuma amostra foi executada')
        self.sample_label = tk.StringVar(value='Selecione JAR, CLASS, EXE ou DLL para começar')
        self.hash_label = tk.StringVar(value='SHA-256 —')
        self.search_path = tk.StringVar()
        self.query = tk.StringVar()
        self.mapped = tk.BooleanVar(value=False)
        self.search_mode = tk.StringVar(value='strings')
        self.patch_name = tk.StringVar()
        self.patch_rva = tk.StringVar()
        self.expected = tk.StringVar()
        self.replacement = tk.StringVar()
        self.signature_size = tk.StringVar(value='16')
        self.preset = tk.StringVar(value='Personalizado')
        self.capture = tk.BooleanVar(value=True)
        self.offline = tk.BooleanVar(value=True)
        self.memory = tk.StringVar(value='4096')
        self.package_label = tk.StringVar(value='Exporte um pacote para preparar o teste')
        self._layout()
        self.search_path.trace_add('write', self._invalidate_search)
        self.mapped.trace_add('write', self._invalidate_search)
        self.root.after(100, self._poll)

    def _invalidate_search(self, *_):
        self.view = self.hit_view = None
        self.hits = []
        self.results.delete(*self.results.get_children())

    def _style(self):
        style = ttk.Style(self.root)
        style.theme_use('clam')
        self.root.option_add('*Font', ('Segoe UI', 10))
        style.configure('.', background='#161e2b', foreground='#e6ecf7', fieldbackground='#0e1420', bordercolor='#2b374b')
        style.configure('TFrame', background='#161e2b')
        style.configure('TLabel', background='#161e2b', foreground='#e6ecf7')
        style.configure('Muted.TLabel', foreground='#9babc3')
        style.configure('Heading.TLabel', font=('Segoe UI', 20, 'bold'))
        style.configure('Section.TLabel', font=('Segoe UI', 12, 'bold'))
        style.configure('TButton', padding=(12, 8), background='#25344b')
        style.map('TButton', background=[('active', '#344962')])
        style.configure('Accent.TButton', background='#5266dc', foreground='white')
        style.map('Accent.TButton', background=[('active', '#6679ef')])
        style.configure('TEntry', padding=6, foreground='#edf2ff', insertcolor='white')
        style.configure('TNotebook', background='#10151f', borderwidth=0)
        style.configure('TNotebook.Tab', padding=(20, 10), background='#202c40')
        style.map('TNotebook.Tab', background=[('selected', '#5266dc')], foreground=[('selected', 'white')])
        style.configure('Treeview', background='#101824', fieldbackground='#101824', foreground='#dce5f4', rowheight=28)
        style.configure('Treeview.Heading', background='#25344b', foreground='#e6ecf7', padding=6)
        style.map('Treeview', background=[('selected', '#394d88')])

    def _layout(self):
        outer = ttk.Frame(self.root, padding=22)
        outer.pack(fill='both', expand=True, padx=12, pady=12)
        header = ttk.Frame(outer)
        header.pack(fill='x')
        ttk.Label(header, text='UNVEIL', style='Heading.TLabel').pack(side='left')
        ttk.Label(header, text='  /  Patch Workbench', style='Muted.TLabel').pack(side='left', padx=12)
        ttk.Button(header, text='Abrir projeto', command=self.open_project).pack(side='right')
        ttk.Button(header, text='Salvar projeto', command=self.save_project).pack(side='right', padx=8)
        ttk.Label(outer, text='JVM / PE · Análise → Strings → Patches → Teste isolado', style='Muted.TLabel').pack(anchor='w', pady=(8, 18))
        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill='both', expand=True)
        self.sample_tab = ttk.Frame(self.tabs, padding=18)
        self.search_tab = ttk.Frame(self.tabs, padding=18)
        self.strings_tab = ttk.Frame(self.tabs, padding=18)
        self.patch_tab = ttk.Frame(self.tabs, padding=18)
        self.sandbox_tab = ttk.Frame(self.tabs, padding=18)
        self.log_tab = ttk.Frame(self.tabs, padding=18)
        for tab, label in [(self.sample_tab, '01  Amostra'), (self.search_tab, '02  Busca'),
                           (self.strings_tab, '03  Strings'),
                           (self.patch_tab, '04  Patches'), (self.sandbox_tab, '05  Sandbox'), (self.log_tab, 'Registro')]:
            self.tabs.add(tab, text=label)
        self._sample_layout()
        self._search_layout()
        self._strings_layout()
        self._patch_layout()
        self._sandbox_layout()
        self.log = tk.Text(self.log_tab, bg='#0e1420', fg='#bacbe5', insertbackground='white', relief='flat', font=('Consolas', 10), wrap='word')
        self.log.pack(fill='both', expand=True)
        ttk.Label(outer, textvariable=self.status, style='Muted.TLabel').pack(anchor='w', pady=(14, 0))

    def _sample_layout(self):
        tab = self.sample_tab
        ttk.Label(tab, text='Seu ponto de partida', style='Section.TLabel').pack(anchor='w')
        ttk.Label(tab, text='A análise e a busca leem arquivos. A execução acontece somente ao abrir um teste ou aplicador.',
                  style='Muted.TLabel', wraplength=1000).pack(anchor='w', pady=(6, 16))
        row = ttk.Frame(tab)
        row.pack(fill='x')
        ttk.Button(row, text='Selecionar amostra', style='Accent.TButton', command=self.choose_sample).pack(side='left')
        ttk.Button(row, text='Analisar com Unveil', command=self.analyze_sample).pack(side='left', padx=8)
        ttk.Button(row, text='Capturar PID existente', command=self.capture_pid).pack(side='left')
        ttk.Label(tab, textvariable=self.sample_label, wraplength=1000).pack(anchor='w', pady=(20, 8))
        ttk.Label(tab, textvariable=self.hash_label, style='Muted.TLabel', wraplength=1000).pack(anchor='w')
        ttk.Label(tab, text='Relatório da análise', style='Section.TLabel').pack(anchor='w', pady=(22, 8))
        self.analysis = tk.Text(tab, bg='#0e1420', fg='#dce5f4', relief='flat', font=('Consolas', 10), wrap='word', height=12)
        self.analysis.pack(fill='both', expand=True)
        self.analysis.insert('end', 'Selecione uma amostra e clique em Analisar.\n\nO Unveil identifica seções, imports e indícios de proteção.\nUm dump de memória não equivale a remover VMProtect.')

    def _strings_layout(self):
        tab = self.strings_tab
        ttk.Label(tab, text='Recuperação automática de padrões reconhecidos', style='Section.TLabel').pack(anchor='w')
        ttk.Label(tab, text='JAR: avaliação estática e reconstrução verificada. CLASS: análise. '
                  'PE: candidatos de XOR constante em buffers na stack.', wraplength=1000,
                  style='Muted.TLabel').pack(anchor='w', pady=12)
        ttk.Checkbutton(tab, text='Offline: usar dependências ASM já instaladas (JVM)', variable=self.offline).pack(anchor='w')
        ttk.Button(tab, text='Recuperar strings e exportar TXT / JAR', style='Accent.TButton',
                   command=self.recover_strings).pack(anchor='w', pady=20)
        self.string_report = tk.Text(tab, bg='#0e1420', fg='#dce5f4', relief='flat',
                                     font=('Consolas', 10), wrap='word')
        self.string_report.pack(fill='both', expand=True)
        self.string_report.insert('end', 'Saída em uma pasta nova:\n  decrypted-strings.txt\n  visible-strings.txt\n'
                                  '  strings-report.json\n  recovered.jar (somente JAR)\n\n'
                                  'Nenhum código alvo é executado. Padrões não suportados permanecem sem solução.\n'
                                  'Os textos recuperados e os textos apenas visíveis ficam separados.')

    def recover_strings(self):
        if self.artifact is None:
            self._error(ValueError('Selecione uma amostra primeiro.'))
            return
        parent = filedialog.askdirectory(parent=self.root, title='Pasta pai da exportação de strings')
        if not parent:
            return
        source, offline = self.artifact.path, self.offline.get()
        suggested = suggested_destination(Path(parent))
        destination = suggested.with_name(suggested.name.replace('Unveil-patch-', 'Unveil-strings-', 1))
        from unveil.strings import recover_strings
        def done(report):
            self.string_report.delete('1.0', 'end')
            self.string_report.insert('end', json.dumps(report, indent=2, ensure_ascii=True)[:100000])
            self.log.insert('end', f'Strings exportadas: {destination}\nAmostra não executada.\n')
        self._submit('Recuperando strings', lambda: recover_strings(source, destination, offline), done)

    def _search_layout(self):
        tab = self.search_tab
        row = ttk.Frame(tab)
        row.pack(fill='x')
        ttk.Entry(row, textvariable=self.search_path).pack(side='left', fill='x', expand=True)
        ttk.Button(row, text='Arquivo / dump', command=self.choose_view).pack(side='left', padx=(8, 0))
        mode = ttk.Frame(tab)
        mode.pack(fill='x', pady=12)
        ttk.Checkbutton(mode, text='Layout de memória (.mapped.bin): offset = RVA', variable=self.mapped).pack(side='left')
        ttk.Button(mode, text='Importar resultado do Sandbox', command=self.import_result).pack(side='right')
        row = ttk.Frame(tab)
        row.pack(fill='x')
        ttk.Entry(row, textvariable=self.query).pack(side='left', fill='x', expand=True)
        ttk.Combobox(row, textvariable=self.search_mode, values=('strings', 'hex'), state='readonly', width=10).pack(side='left', padx=8)
        ttk.Button(row, text='Buscar', style='Accent.TButton', command=self.search).pack(side='left')
        self.results = self._tree(tab, ('rva', 'offset', 'encoding', 'text'), ('RVA', 'Offset', 'Tipo', 'Conteúdo'), (110, 110, 100, 660))
        self.results.bind('<Double-1>', lambda event: self.use_hit())
        row = ttk.Frame(tab)
        row.pack(fill='x', pady=(10, 0))
        ttk.Button(row, text='Usar RVA no editor', command=self.use_hit).pack(side='left')
        ttk.Button(row, text='Criar troca de texto', command=self.replace_text).pack(side='left', padx=8)
        ttk.Label(row, text='Até 2.500 resultados por busca · strings visíveis, sem decriptação automática', style='Muted.TLabel').pack(side='right')

    def _patch_layout(self):
        tab = self.patch_tab
        ttk.Label(tab, text='Construa a alteração sem escrever PowerShell', style='Section.TLabel').pack(anchor='w')
        ttk.Label(tab, text='RVA em hexadecimal + assinatura original + bytes novos. O exportador verifica limites e sobreposições.',
                  style='Muted.TLabel').pack(anchor='w', pady=(6, 12))
        form = ttk.Frame(tab)
        form.pack(fill='x')
        form.columnconfigure(1, weight=1)
        for index, (label, variable) in enumerate([('Nome', self.patch_name), ('RVA (hex)', self.patch_rva),
                                                  ('Bytes esperados', self.expected), ('Bytes novos', self.replacement)]):
            ttk.Label(form, text=label).grid(row=index, column=0, sticky='w', padx=(0, 12), pady=4)
            ttk.Entry(form, textvariable=variable).grid(row=index, column=1, sticky='ew', pady=4)
        row = ttk.Frame(tab)
        row.pack(fill='x', pady=12)
        ttk.Combobox(row, textvariable=self.preset, state='readonly', width=25,
                     values=('Personalizado', 'Retornar zero / false', 'Retornar um / true', 'Retornar sem valor')).pack(side='left')
        self.preset.trace_add('write', self._apply_preset)
        ttk.Label(row, text='Assinatura:').pack(side='left', padx=(14, 5))
        ttk.Spinbox(row, textvariable=self.signature_size, from_=1, to=4096, width=6).pack(side='left')
        ttk.Button(row, text='Ler do arquivo / dump', command=self.read_signature).pack(side='left', padx=8)
        ttk.Button(row, text='Adicionar / salvar', style='Accent.TButton', command=self.add_patch).pack(side='right')
        self.patch_list = self._tree(tab, ('name', 'rva', 'expected', 'new'), ('Nome', 'RVA', 'Esperado', 'Novo'), (220, 110, 350, 350))
        self.patch_list.bind('<Double-1>', lambda event: self.edit_patch())
        row = ttk.Frame(tab)
        row.pack(fill='x', pady=(10, 0))
        ttk.Button(row, text='Editar selecionado', command=self.edit_patch).pack(side='left')
        ttk.Button(row, text='Remover', command=self.remove_patch).pack(side='left', padx=8)
        ttk.Button(row, text='Novo patch', command=self.clear_editor).pack(side='left')
        ttk.Button(row, text='Importar lista JSON', command=self.import_patch_list).pack(side='right')

    def _sandbox_layout(self):
        tab = self.sandbox_tab
        ttk.Label(tab, text='Prepare o experimento', style='Section.TLabel').pack(anchor='w')
        ttk.Label(tab, text='O Sandbox usa rede desativada, entrada somente leitura e uma pasta de saída por sessão.',
                  style='Muted.TLabel', wraplength=1000).pack(anchor='w', pady=(6, 18))
        row = ttk.Frame(tab)
        row.pack(fill='x')
        ttk.Label(row, text='Título exato da janela antes do patch:').pack(side='left')
        ttk.Entry(row, textvariable=self.title, width=32).pack(side='left', padx=12)
        row = ttk.Frame(tab)
        row.pack(fill='x', pady=16)
        ttk.Checkbutton(row, text='Capturar módulo em memória após o patch', variable=self.capture).pack(side='left')
        ttk.Label(row, text='RAM do Sandbox (MiB):').pack(side='left', padx=(25, 8))
        ttk.Combobox(row, textvariable=self.memory, values=('2048', '4096', '6144', '8192'), state='readonly', width=9).pack(side='left')
        ttk.Label(tab, text='Você pode exportar sem patches para comparar a amostra original. '
                  'O teste espera a janela e as assinaturas; esse momento precisa ser validado para cada programa.',
                  style='Muted.TLabel', wraplength=1000).pack(anchor='w', pady=(0, 20))
        row = ttk.Frame(tab)
        row.pack(fill='x')
        ttk.Button(row, text='Exportar Windows + Sandbox', style='Accent.TButton', command=self.export).pack(side='left')
        ttk.Button(row, text='Abrir Sandbox do pacote', command=self.launch_sandbox).pack(side='left', padx=8)
        ttk.Button(row, text='Abrir pasta', command=self.open_package_folder).pack(side='left')
        ttk.Label(tab, textvariable=self.package_label, wraplength=1000).pack(anchor='w', pady=20)
        self.preview = tk.Text(tab, bg='#0e1420', fg='#bacbe5', relief='flat', font=('Consolas', 10), height=9, wrap='word')
        self.preview.pack(fill='both', expand=True)
        self.preview.insert('end', 'Arquivos gerados:\n  windows/Aplicar-Patch.cmd\n  windows-sandbox/Abrir-Sandbox.cmd\n  input/patch.ps1 + runtime.json + sample.exe em cada pasta\n\nWindows Sandbox deve estar instalado. O Unveil não altera BIOS ou recursos do Windows.\n\nA edição no-code cobre bytes e textos que cabem no espaço original.\nPonteiros de ícones e alocações de strings exigem uma etapa especializada.')

    def _tree(self, parent, columns, headings, widths):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True, pady=(12, 0))
        tree = ttk.Treeview(frame, columns=columns, show='headings', selectmode='browse', height=6)
        scrollbar = ttk.Scrollbar(frame, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        for column, heading, width in zip(columns, headings, widths):
            tree.heading(column, text=heading)
            tree.column(column, width=width, minwidth=60)
        tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        return tree

    def _error(self, exc):
        self.status.set('Falha · ' + str(exc)[:180])
        self.log.insert('end', f'\n{type(exc).__name__}: {exc}\n')
        self.log.see('end')
        messagebox.showerror('Unveil', str(exc), parent=self.root)

    def _submit(self, label, task, callback):
        if self.pending is not None:
            messagebox.showinfo('Unveil', 'Aguarde a operação atual.', parent=self.root)
            return
        self.status.set(label + '…')
        self.log.insert('end', '\n' + label + '\n')
        self.callback = callback
        self.pending = self.executor.submit(task)

    def _poll(self):
        if self.closed:
            return
        if self.pending is not None and self.pending.done():
            future, callback = self.pending, self.callback
            self.pending = self.callback = None
            try:
                callback(future.result())
                self.status.set('Concluído')
            except Exception as exc:  # GUI operation boundary: report, never silently suppress.
                self._error(exc)
        self.root.after(100, self._poll)

    def _require_project(self) -> Project:
        if self.project is None:
            raise ValueError('O editor PS1 exige um EXE AMD64. JVM e outros PEs aceitam análise e recuperação de strings.')
        return replace(self.project, title=self.title.get(), capture=self.capture.get(), memory_mb=int(self.memory.get())).validated()

    def _set_project(self, project):
        self.project = project
        self.artifact = InputArtifact.open(project.source)
        self.package = None
        self.package_label.set('Exporte um pacote para preparar o teste')
        self.title.set(project.title)
        self.capture.set(project.capture)
        self.memory.set(str(project.memory_mb))
        self.sample_label.set(f'{project.source}\nImagem: {project.image_size:,} bytes · AMD64')
        self.hash_label.set('SHA-256  ' + project.sha256)
        self.search_path.set(project.source)
        self.mapped.set(False)
        self.view = None
        self.clear_editor()
        self._refresh_patches()

    def choose_sample(self):
        path = filedialog.askopenfilename(parent=self.root, title='Amostra JVM / PE', filetypes=[('JVM / PE', '*.jar *.class *.exe *.dll'), ('Todos', '*.*')])
        if path:
            self.load_sample(path)

    def load_sample(self, path):
        def task():
            artifact = InputArtifact.open(path)
            project = None
            if artifact.type == 'PE':
                try:
                    project = Project.open_sample(path)
                except ValueError:
                    pass  # PE32 and DLL still support analysis and string recovery.
            return artifact, project
        def done(result):
            artifact, project = result
            if project:
                self._set_project(project)
            else:
                self.artifact, self.project, self.package = artifact, None, None
                self.sample_label.set(f'{artifact.path}\nFormato: {artifact.type} · {artifact.size:,} bytes')
                self.hash_label.set('SHA-256  ' + artifact.sha256)
                self.search_path.set(str(artifact.path) if artifact.type == 'PE' else '')
                self.mapped.set(False)
                self.clear_editor()
                self._refresh_patches()
                self.package_label.set('Aplicadores PS1 exigem um EXE AMD64; análise e strings estão disponíveis.')
        self._submit('Lendo amostra', task, done)

    def analyze_sample(self):
        try:
            if self.artifact is None:
                raise ValueError('Selecione uma amostra primeiro.')
            source = self.artifact.path
            from unveil.core.engine import analyze
            def done(report):
                text = json.dumps(report, indent=2, ensure_ascii=False)
                self.analysis.delete('1.0', 'end')
                self.analysis.insert('end', text[:100000] + ('\n[Visualização limitada a 100.000 caracteres]' if len(text) > 100000 else ''))
                self.log.insert('end', 'Análise estática concluída; amostra não executada.\n')
            self._submit('Analisando pelo motor Unveil', lambda: analyze(source, 'analyze'), done)
        except (ValueError, OSError) as exc:
            self._error(exc)

    def choose_view(self):
        path = filedialog.askopenfilename(parent=self.root, title='Arquivo PE ou imagem mapeada', filetypes=[('PE / memória', '*.exe *.dll *.bin'), ('Todos', '*.*')])
        if path:
            self.search_path.set(path)
            self.mapped.set(path.lower().endswith('.mapped.bin'))
            self.view = None

    def search(self):
        path, mapped, query, mode = self.search_path.get(), self.mapped.get(), self.query.get(), self.search_mode.get()
        if not path:
            self._error(ValueError('Escolha um arquivo ou dump.'))
            return
        def task():
            view = BinaryView(Path(path), mapped)
            return view, view.search(query, mode)
        def done(result):
            if path != self.search_path.get() or mapped != self.mapped.get():
                self.log.insert('end', 'Busca descartada: o arquivo ou layout mudou.\n')
                return
            self.view, self.hits = result
            self.hit_view = self.view
            self.results.delete(*self.results.get_children())
            for index, hit in enumerate(self.hits):
                self.results.insert('', 'end', iid=str(index), values=(f'0x{hit.rva:08x}' if hit.rva is not None else '—',
                                    f'0x{hit.offset:08x}', hit.encoding, hit.text))
            self.log.insert('end', f'{len(self.hits)} resultados. Layout: {"memória" if mapped else "arquivo"}.\n')
        self._submit('Buscando', task, done)

    def _selected_hit(self) -> Hit:
        selection = self.results.selection()
        if not selection:
            raise ValueError('Selecione um resultado da busca.')
        return self.hits[int(selection[0])]

    def use_hit(self):
        try:
            hit = self._selected_hit()
            if hit.rva is None:
                raise ValueError('O resultado não pertence a uma região mapeada do módulo.')
            self.clear_editor()
            self.patch_rva.set(f'0x{hit.rva:x}')
            self.patch_name.set('patch-' + f'{hit.rva:x}')
            self.tabs.select(self.patch_tab)
            self.read_signature()
        except (ValueError, OSError) as exc:
            self._error(exc)

    def replace_text(self):
        try:
            hit = self._selected_hit()
            if self.hit_view is None:
                raise ValueError('Carregue um arquivo primeiro.')
            value = simpledialog.askstring('Trocar texto', 'Novo texto (precisa caber no espaço original):', parent=self.root)
            if value is None:
                return
            expected, patch = self.hit_view.text_patch(hit, value)
            self.clear_editor()
            self.patch_name.set('texto-' + f'{hit.rva:x}')
            self.patch_rva.set(f'0x{hit.rva:x}')
            self.expected.set(expected)
            self.replacement.set(patch)
            self.tabs.select(self.patch_tab)
        except (ValueError, OSError, UnicodeError) as exc:
            self._error(exc)

    def _apply_preset(self, *_):
        values = {'Retornar zero / false': '31 C0 C3', 'Retornar um / true': 'B8 01 00 00 00 C3', 'Retornar sem valor': 'C3'}
        if self.preset.get() in values:
            self.replacement.set(values[self.preset.get()])

    def read_signature(self):
        try:
            rva_text = self.patch_rva.get()
            rva, size = parse_rva(rva_text), int(self.signature_size.get())
            path, mapped = self.search_path.get(), self.mapped.get()
            def done(result):
                if (path != self.search_path.get() or mapped != self.mapped.get()
                        or self.patch_rva.get() != rva_text):
                    return
                self.view, content = result
                self.expected.set(content.hex(' '))
            def task():
                view = BinaryView(Path(path), mapped)
                return view, view.read_rva(rva, size)
            self._submit('Lendo assinatura por RVA', task, done)
        except (ValueError, OSError) as exc:
            self._error(exc)

    def add_patch(self):
        try:
            project = self._require_project()
            patch = Patch(self.patch_name.get(), parse_rva(self.patch_rva.get()), self.expected.get(), self.replacement.get())
            patches = list(project.patches)
            if self.edit_index is None:
                patches.append(patch)
            else:
                patches[self.edit_index] = patch
            self.project = replace(project, patches=tuple(patches)).validated()
            self._refresh_patches()
            self.clear_editor()
        except (ValueError, OSError) as exc:
            self._error(exc)

    def _refresh_patches(self):
        self.patch_list.delete(*self.patch_list.get_children())
        if self.project:
            for index, patch in enumerate(self.project.patches):
                self.patch_list.insert('', 'end', iid=str(index), values=(patch.name, f'0x{patch.rva:x}', patch.expected_hex, patch.replacement_hex))

    def edit_patch(self):
        if not self.patch_list.selection() or not self.project:
            return
        self.edit_index = int(self.patch_list.selection()[0])
        patch = self.project.patches[self.edit_index]
        self.patch_name.set(patch.name)
        self.patch_rva.set(f'0x{patch.rva:x}')
        self.expected.set(patch.expected_hex)
        self.replacement.set(patch.replacement_hex)

    def remove_patch(self):
        if not self.patch_list.selection() or not self.project:
            return
        index = int(self.patch_list.selection()[0])
        self.project = replace(self.project, patches=tuple(p for i, p in enumerate(self.project.patches) if i != index))
        self.clear_editor()
        self._refresh_patches()

    def clear_editor(self):
        self.edit_index = None
        for variable in (self.patch_name, self.patch_rva, self.expected, self.replacement):
            variable.set('')
        self.preset.set('Personalizado')

    def import_patch_list(self):
        try:
            project = self._require_project()
            path = filedialog.askopenfilename(parent=self.root, title='Lista de patches (name/rva/expectedHex/patchHex)', filetypes=[('JSON', '*.json')])
            if path:
                patches = import_patches(Path(path), project.image_size)
                self.project = replace(project, patches=project.patches + patches).validated()
                self._refresh_patches()
        except (ValueError, OSError, TypeError) as exc:
            self._error(exc)

    def save_project(self):
        try:
            project = self._require_project()
            path = filedialog.asksaveasfilename(parent=self.root, defaultextension='.json', title='Salvar projeto', filetypes=[('Projeto Unveil', '*.json')])
            if path:
                project.save(Path(path))
                self.status.set('Projeto salvo')
        except (ValueError, OSError) as exc:
            self._error(exc)

    def open_project(self):
        path = filedialog.askopenfilename(parent=self.root, title='Projeto Unveil', filetypes=[('JSON', '*.json')])
        if path:
            self.load_project(path)

    def load_project(self, path):
        self._submit('Abrindo projeto', lambda: Project.load(Path(path)), self._set_project)

    def export(self):
        try:
            project = self._require_project()
            parent = filedialog.askdirectory(parent=self.root, title='Pasta pai do novo pacote')
            if parent:
                destination = suggested_destination(Path(parent))
                def done(path):
                    self.package = path
                    self.package_label.set(str(path))
                    self.log.insert('end', f'Pacote gerado: {path}\nNenhuma amostra foi executada.\n')
                self._submit('Gerando scripts e pacote', lambda: export_package(project, destination), done)
        except (ValueError, OSError) as exc:
            self._error(exc)

    def launch_sandbox(self):
        if self.package is None:
            self._error(ValueError('Exporte um pacote primeiro.'))
            return
        package = self.package
        self._submit('Abrindo Windows Sandbox', lambda: open_sandbox(package), lambda result: self.log.insert('end', result + '\n'))

    def open_package_folder(self):
        try:
            if self.package is None or not self.package.is_dir():
                raise ValueError('Exporte um pacote primeiro.')
            if os.name != 'nt':
                raise ValueError('Abrir pasta está disponível no Windows.')
            os.startfile(self.package)
        except (ValueError, OSError) as exc:
            self._error(exc)

    def import_result(self):
        path = filedialog.askopenfilename(parent=self.root, title='Resultado do teste', filetypes=[('Resultado JSON', '*.json')])
        if not path:
            return
        try:
            result_path = Path(path)
            if result_path.stat().st_size > 4 * 1024 * 1024:
                raise ValueError('Relatório maior que 4 MiB.')
            result = json.loads(result_path.read_text(encoding='utf-8-sig'))
            if not isinstance(result, dict):
                raise ValueError('O relatório precisa ser um objeto JSON.')
            self.log.insert('end', '\nResultado do teste:\n' + json.dumps(result, indent=2, ensure_ascii=False)[:12000] + '\n')
            dump = result_path.parent / 'module.mapped.bin'
            if dump.is_file():
                self.search_path.set(str(dump))
                self.mapped.set(True)
                self.view = None
                self.tabs.select(self.search_tab)
            else:
                self.tabs.select(self.log_tab)
        except (ValueError, OSError) as exc:
            self._error(exc)

    def capture_pid(self):
        try:
            project = self._require_project()
            if os.name != 'nt':
                raise ValueError('Captura de processo exige Windows.')
            pid = simpledialog.askinteger('Capturar memória', 'PID de um processo já aberto da amostra selecionada:', parent=self.root, minvalue=1)
            if pid is None:
                return
            path = filedialog.asksaveasfilename(parent=self.root, title='Salvar imagem por RVA', defaultextension='.mapped.bin', filetypes=[('Memória', '*.mapped.bin')])
            if not path:
                return
            destination = Path(path).resolve()
            if not str(destination).lower().endswith('.mapped.bin') or destination == Path(project.source).resolve():
                raise ValueError('Use um novo arquivo .mapped.bin, separado da amostra.')
            if destination.exists():
                raise ValueError('Escolha um nome novo para não sobrescrever outra captura.')
            report_path = destination.with_suffix('.json')
            if report_path.exists() or report_path == Path(project.source).resolve():
                raise ValueError('O destino do relatório já existe. Escolha outro nome.')
            from unveil.native.live_dump import dump
            def done(result):
                with report_path.open('x', encoding='utf-8') as stream:
                    stream.write(json.dumps(result, indent=2))
                self.search_path.set(str(destination))
                self.mapped.set(True)
                self.view = None
                self.log.insert('end', f'Captura somente leitura: {destination}\n')
                self.tabs.select(self.search_tab)
            self._submit('Capturando módulo do processo existente', lambda: dump(pid, project.source, destination, timeout=30), done)
        except (ValueError, OSError) as exc:
            self._error(exc)

    def close(self):
        self.closed = True
        self.executor.shutdown(wait=False, cancel_futures=True)
        self.root.destroy()
