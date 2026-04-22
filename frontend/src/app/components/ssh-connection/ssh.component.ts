import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';
import { LogService } from '../../services/log.service';
import { SidebarComponent } from '../sidebar/sidebar.component';

@Component({
  selector: 'app-ssh-connection',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterModule, SidebarComponent],
  template: `
    <div class="flex h-screen bg-slate-100">
      <app-sidebar></app-sidebar>

      <!-- Main Content -->
      <main class="flex-1 ml-64 overflow-auto p-8">
        <div class="max-w-4xl mx-auto">
          <header class="mb-8">
            <h2 class="text-3xl font-bold text-slate-800">Analyse de Logs SSH</h2>
            <p class="text-slate-500">Connectez-vous à un serveur distant pour extraire et analyser les logs en temps réel</p>
          </header>

          <div class="grid grid-cols-3 gap-8">
            <!-- Form Column -->
            <div class="col-span-2 space-y-6">
              <div class="bg-white rounded-2xl shadow-card p-8 border border-slate-200">
                <form (ngSubmit)="onSubmit()" class="space-y-5">
                  <div class="grid grid-cols-2 gap-5">
                    <div>
                      <label class="block text-xs font-bold text-slate-500 uppercase mb-2">Adresse IP / Host</label>
                      <input type="text" [(ngModel)]="form.host" name="host" required
                             class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition"
                             placeholder="192.168.1.100">
                    </div>
                    <div>
                      <label class="block text-xs font-bold text-slate-500 uppercase mb-2">Utilisateur</label>
                      <input type="text" [(ngModel)]="form.user" name="user" required
                             class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition"
                             placeholder="root">
                    </div>
                  </div>

                  <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase mb-2">Mot de passe</label>
                    <div class="relative">
                      <input [type]="showPassword ? 'text' : 'password'" [(ngModel)]="form.pass" name="pass" required
                             class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition"
                             placeholder="••••••••">
                      <button type="button" (click)="showPassword = !showPassword" class="absolute right-4 top-3.5 text-slate-400">
                        <i class="fas" [class.fa-eye]="!showPassword" [class.fa-eye-slash]="showPassword"></i>
                      </button>
                    </div>
                  </div>

                  <div>
                    <label class="block text-xs font-bold text-slate-500 uppercase mb-2">Chemin du fichier log</label>
                    <input type="text" [(ngModel)]="form.filePath" name="filePath" required
                           class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition"
                           placeholder="/var/log/syslog">
                  </div>

                  <div class="grid grid-cols-2 gap-5">
                    <div>
                      <label class="block text-xs font-bold text-slate-500 uppercase mb-2">Nombre de lignes</label>
                      <input type="number" [(ngModel)]="form.numLines" name="numLines"
                             class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition"
                             placeholder="100">
                    </div>
                    <div>
                      <label class="block text-xs font-bold text-slate-500 uppercase mb-2">Date spécifique (Optionnel)</label>
                      <input type="date" [(ngModel)]="form.specificDate" name="specificDate"
                             class="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl focus:ring-2 focus:ring-indigo-500 outline-none transition">
                    </div>
                  </div>

                  <div class="pt-4 flex flex-col gap-3">
                    <button type="submit" [disabled]="loading"
                            class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-4 rounded-xl transition disabled:opacity-50 shadow-indigo flex items-center justify-center gap-3">
                      <i class="fas" [class.fa-search]="!loading" [class.fa-spinner]="loading" [class.fa-spin]="loading"></i>
                      {{ loading ? 'Analyse en cours...' : "Lancer l'analyse" }}
                    </button>
                    
                    <div class="grid grid-cols-2 gap-3">
                      <button type="button" (click)="analyzeToday()" [disabled]="loading"
                              class="flex-1 bg-slate-800 hover:bg-slate-900 text-white font-bold py-3 rounded-xl transition text-sm">
                        Logs d'aujourd'hui
                      </button>
                      <button type="button" (click)="chooseDate()" [disabled]="loading"
                              class="flex-1 border border-slate-300 hover:bg-slate-50 text-slate-700 font-bold py-3 rounded-xl transition text-sm">
                        Choisir une date
                      </button>
                    </div>
                  </div>
                </form>

                <div *ngIf="error" class="mt-6 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 flex items-center gap-3">
                  <i class="fas fa-exclamation-circle"></i>
                  <span class="text-sm font-medium">{{ error }}</span>
                </div>

                <div *ngIf="success" class="mt-6 p-6 bg-emerald-50 border border-emerald-200 rounded-xl text-emerald-700">
                  <div class="flex items-center gap-3 mb-2">
                    <i class="fas fa-check-circle text-xl"></i>
                    <span class="font-bold">Analyse terminée avec succès !</span>
                  </div>
                  <p class="text-sm mb-4">Les données ont été traitées par l'IA et sont disponibles dans votre rapport.</p>
                  <a routerLink="/report" [queryParams]="{id: lastAnalysisId}" 
                     class="inline-block bg-emerald-600 text-white px-6 py-2 rounded-lg font-bold hover:bg-emerald-700 transition">
                    Consulter le Rapport
                  </a>
                </div>
              </div>
            </div>

            <!-- Help/Info Column -->
            <div class="col-span-1 space-y-6">
              <div class="bg-indigo-600 rounded-2xl p-6 text-white shadow-indigo">
                <h3 class="font-bold mb-4 flex items-center gap-2">
                  <i class="fas fa-info-circle"></i>
                  Conseils d'Analyse
                </h3>
                <ul class="text-sm space-y-3 text-indigo-100">
                  <li class="flex gap-2">
                    <i class="fas fa-caret-right mt-1"></i>
                    Utilisez un compte avec des droits de lecture sur les fichiers logs.
                  </li>
                  <li class="flex gap-2">
                    <i class="fas fa-caret-right mt-1"></i>
                    Le format de date doit correspondre aux logs du serveur (ex: Jan 10).
                  </li>
                  <li class="flex gap-2">
                    <i class="fas fa-caret-right mt-1"></i>
                    L'IA SOC priorise les erreurs de type "Authentication failure" et "Root access".
                  </li>
                </ul>
              </div>

              <div class="bg-white rounded-2xl p-6 border border-slate-200 shadow-card">
                <h3 class="font-bold text-slate-800 mb-4 flex items-center gap-2">
                  <i class="fas fa-shield-alt text-indigo-600"></i>
                  Sécurité
                </h3>
                <p class="text-xs text-slate-500 leading-relaxed">
                  Vos identifiants SSH sont cryptés avec l'algorithme AES-256 avant d'être envoyés et ne sont jamais stockés en clair.
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
  form = { 
    host: '', 
    user: '', 
    pass: '', 
    filePath: '/var/log/syslog', 
    numLines: 100,
    specificDate: ''
  };
  loading = false;
  error = '';
  success = false;
  showPassword = false;
  lastAnalysisId: number | null = null;

  constructor(private logService: LogService) {}

  ngOnInit(): void {}

  onSubmit(): void {
    this.loading = true;
    this.error = '';
    this.success = false;

    // Use a clean payload for the service
    const payload = {
      host: this.form.host,
      user: this.form.user,
      pass: this.form.pass,
      numLines: this.form.numLines,
      filePath: this.form.filePath,
      specificDate: this.form.specificDate
    };

    this.logService.analyzeSshLog(payload as any).subscribe({
      next: (response) => {
        this.loading = false;
        if (response?.status === 'success') {
          this.success = true;
          this.lastAnalysisId = response.analysis_id || null;
          return;
        }
        this.error = response?.message || `Erreur lors de l'analyse SSH`;
      },
      error: (err) => {
        this.loading = false;
        this.error = err.error?.message || `Erreur lors de l'analyse SSH`;
      }
    });
  }

  analyzeToday(): void {
    const today = new Date().toISOString().split('T')[0];
    this.form.specificDate = today;
    this.onSubmit();
  }

  chooseDate(): void {
    const dateInput = document.querySelector('input[type="date"]') as HTMLInputElement;
    if (dateInput) dateInput.showPicker();
  }
}

