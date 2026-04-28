import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { LogService } from '../../services/log.service';
import { SidebarComponent } from '../sidebar/sidebar.component';

@Component({
  selector: 'app-ssh-connection',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule, SidebarComponent],
  template: `
    <div class="flex h-screen bg-slate-900 text-slate-100">
      <app-sidebar></app-sidebar>

      <main class="flex-1 ml-64 overflow-auto p-8 bg-[#0d1117]">
        <div class="max-w-6xl mx-auto">
          <header class="mb-10">
            <div class="flex items-center gap-4 mb-2">
              <div class="p-3 bg-indigo-600/20 rounded-xl shadow-indigo-lg">
                <i class="fas fa-server text-2xl text-indigo-500"></i>
              </div>
              <h2 class="text-3xl font-black tracking-tight text-white uppercase italic">Analyse <span class="text-indigo-500">SSH</span> SOC</h2>
            </div>
            <p class="text-slate-500 font-medium">Terminal d'extraction et d'analyse de logs distants sécurisé</p>
          </header>

          <div class="grid grid-cols-12 gap-8">
            <!-- Formulaire de Connexion -->
            <div class="col-span-8">
              <div class="bg-[#161b22] rounded-2xl border border-white/10 shadow-2xl p-8 relative overflow-hidden">
                <div class="absolute top-0 left-0 w-1 h-full bg-indigo-600"></div>
                
                <form [formGroup]="sshForm" (ngSubmit)="onSubmit()" class="space-y-6">
                  <div class="grid grid-cols-2 gap-6">
                    <div class="space-y-2">
                      <label class="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Adresse IP / Host</label>
                      <input type="text" formControlName="host"
                             class="w-full px-5 py-4 bg-slate-900/50 border border-white/5 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition text-white placeholder-slate-600"
                             placeholder="192.168.1.100">
                    </div>
                    <div class="space-y-2">
                      <label class="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Utilisateur</label>
                      <input type="text" formControlName="user"
                             class="w-full px-5 py-4 bg-slate-900/50 border border-white/5 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition text-white placeholder-slate-600"
                             placeholder="root">
                    </div>
                  </div>

                  <div class="space-y-2">
                    <label class="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Mot de passe</label>
                    <div class="relative">
                      <input [type]="showPassword ? 'text' : 'password'" formControlName="pass"
                             class="w-full px-5 py-4 bg-slate-900/50 border border-white/5 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition text-white placeholder-slate-600"
                             placeholder="••••••••">
                      <button type="button" (click)="showPassword = !showPassword" class="absolute right-5 top-4.5 text-slate-500 hover:text-white transition">
                        <i class="fas" [class.fa-eye]="!showPassword" [class.fa-eye-slash]="showPassword"></i>
                      </button>
                    </div>
                  </div>

                  <div class="space-y-2">
                    <label class="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Chemin du fichier log</label>
                    <input type="text" formControlName="filePath"
                           class="w-full px-5 py-4 bg-slate-900/50 border border-white/5 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition text-white"
                           placeholder="/var/log/syslog">
                  </div>

                  <div class="grid grid-cols-2 gap-6 pt-2">
                    <div class="space-y-2">
                      <label class="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Lignes à extraire</label>
                      <input type="number" formControlName="numLines"
                             class="w-full px-5 py-4 bg-slate-900/50 border border-white/5 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition text-white">
                    </div>
                    <div class="space-y-2">
                      <label class="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Date (Optionnel)</label>
                      <input type="date" formControlName="specificDate"
                             class="w-full px-5 py-4 bg-slate-900/50 border border-white/5 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition text-white">
                    </div>
                  </div>

                  <div class="pt-6">
                    <button type="submit" [disabled]="loading || sshForm.invalid"
                            class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-black py-5 rounded-xl transition disabled:opacity-30 shadow-indigo flex items-center justify-center gap-3 uppercase tracking-widest text-sm">
                      <i class="fas" [class.fa-search]="!loading" [class.fa-spinner]="loading" [class.fa-spin]="loading"></i>
                      {{ loading ? 'Analyse SOC en cours...' : "Lancer l'analyse sécurisée" }}
                    </button>
                  </div>
                </form>

                <!-- Status Messages -->
                <div *ngIf="error" class="mt-6 p-4 bg-red-500/10 border border-red-500/20 rounded-xl text-red-400 text-sm font-bold flex items-center gap-3">
                  <i class="fas fa-shield-virus text-lg"></i>
                  {{ error }}
                </div>

                <div *ngIf="success" class="mt-6 p-6 bg-emerald-500/10 border border-emerald-500/20 rounded-xl">
                  <div class="flex items-center gap-4 mb-4">
                    <div class="w-12 h-12 bg-emerald-500/20 rounded-full flex items-center justify-center text-emerald-500">
                      <i class="fas fa-check-double text-xl"></i>
                    </div>
                    <div>
                      <h4 class="font-black text-white uppercase italic">Analyse Réussie</h4>
                      <p class="text-xs text-emerald-400/80 font-bold">Données traitées et rapport généré</p>
                    </div>
                  </div>
                  <a [routerLink]="['/report']" [queryParams]="{id: lastAnalysisId}"
                     class="flex items-center justify-center gap-2 w-full bg-emerald-600 hover:bg-emerald-700 text-white py-3 rounded-xl font-black uppercase tracking-widest text-xs transition">
                    Consulter le Rapport SOC
                  </a>
                </div>
              </div>
            </div>

            <!-- Sidebar : Historique & Infos -->
            <div class="col-span-4 space-y-6">
              <!-- Connexions Récentes -->
              <div class="bg-[#161b22] rounded-2xl border border-white/10 shadow-xl overflow-hidden">
                <div class="p-5 border-b border-white/5 bg-white/5 flex items-center justify-between">
                  <div class="flex items-center gap-3">
                    <i class="fas fa-history text-indigo-400"></i>
                    <h3 class="font-bold text-[10px] uppercase tracking-widest text-white">Connexions Récentes</h3>
                  </div>
                  <span class="text-[9px] bg-indigo-600/20 text-indigo-400 px-2 py-0.5 rounded-full font-bold">{{ recentConnections.length }}</span>
                </div>
                
                <div class="p-4 space-y-3 max-h-[450px] overflow-y-auto">
                  <div *ngIf="recentConnections.length === 0" class="text-center py-12">
                    <i class="fas fa-terminal text-slate-800 text-3xl mb-3"></i>
                    <p class="text-[10px] text-slate-600 font-bold uppercase tracking-widest">Aucun historique</p>
                  </div>

                  <button *ngFor="let conn of recentConnections" 
                          (click)="fillForm(conn)"
                          class="w-full p-4 rounded-xl bg-slate-900/50 border border-white/5 hover:border-indigo-500/50 hover:bg-indigo-500/5 transition-all text-left group relative overflow-hidden">
                    <div class="absolute left-0 top-0 w-1 h-0 bg-indigo-500 group-hover:h-full transition-all"></div>
                    <div class="flex justify-between items-start mb-2">
                      <span class="text-xs font-black text-white group-hover:text-indigo-400 transition">{{ conn.host }}</span>
                      <i class="fas fa-chevron-right text-[10px] text-slate-700 group-hover:text-indigo-500 transform group-hover:translate-x-1 transition"></i>
                    </div>
                    <div class="flex items-center gap-2 text-[9px] text-slate-500 font-bold uppercase tracking-tighter">
                      <i class="fas fa-user text-[8px]"></i>
                      {{ conn.user }}
                      <span class="text-slate-700">|</span>
                      <i class="fas fa-folder text-[8px]"></i>
                      <span class="truncate">{{ conn.filePath }}</span>
                    </div>
                  </button>
                </div>
              </div>

              <!-- Rappel Sécurité -->
              <div class="bg-indigo-600/5 rounded-2xl p-6 border border-indigo-500/20 relative group overflow-hidden">
                <div class="absolute -right-4 -bottom-4 text-indigo-500/10 text-6xl transform -rotate-12 group-hover:scale-110 transition">
                  <i class="fas fa-user-shield"></i>
                </div>
                <div class="flex items-center gap-3 mb-4">
                  <div class="w-10 h-10 bg-indigo-500/20 rounded-xl flex items-center justify-center text-indigo-500">
                    <i class="fas fa-lock"></i>
                  </div>
                  <h4 class="font-black text-white text-xs uppercase italic">Sécurité End-to-End</h4>
                </div>
                <p class="text-[11px] text-slate-500 leading-relaxed font-medium">
                  Le chiffrement <span class="text-indigo-400 font-bold">AES-256</span> garantit que vos credentials ne sont jamais exposés, même en cas d'accès physique à la machine.
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  `
})
export class SshComponent implements OnInit {
  sshForm: FormGroup;
  loading = false;
  error = '';
  success = false;
  showPassword = false;
  lastAnalysisId: number | null = null;
  recentConnections: any[] = [];

  constructor(private fb: FormBuilder, private logService: LogService) {
    this.sshForm = this.fb.group({
      host: ['', [Validators.required]],
      user: ['', [Validators.required]],
      pass: ['', [Validators.required]],
      filePath: ['/var/log/syslog', [Validators.required]],
      numLines: [null],
      specificDate: ['']
    });
  }

  ngOnInit(): void {
    this.loadRecent();
  }

  loadRecent(): void {
    this.recentConnections = this.logService.getRecentConnections();
  }

  fillForm(conn: any): void {
    this.sshForm.patchValue({
      host: conn.host,
      user: conn.user,
      pass: conn.pass,
      filePath: conn.filePath,
      numLines: conn.numLines || 100,
      specificDate: conn.specificDate || ''
    });
  }

  onSubmit(): void {
    if (this.sshForm.invalid) return;

    this.loading = true;
    this.error = '';
    this.success = false;

    this.logService.analyzeSshLog(this.sshForm.value).subscribe({
      next: (response) => {
        this.loading = false;
        if (response?.status === 'success') {
          this.success = true;
          this.lastAnalysisId = response.analysis_id || null;
          
          // Sauvegarder la connexion réussie
          this.logService.saveConnection(this.sshForm.value);
          this.loadRecent();
          return;
        }
        this.error = response?.message || "Erreur lors de l'analyse SSH";
      },
      error: (err) => {
        this.loading = false;
        this.error = err.error?.message || "Erreur de connexion au serveur SOC";
      }
    });
  }
}
