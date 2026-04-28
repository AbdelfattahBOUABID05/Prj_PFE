import { Component, OnInit, AfterViewInit, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { SidebarComponent } from '../sidebar/sidebar.component';
import { LogService, Analysis } from '../../services/log.service';
import { NotificationService } from '../../services/notification.service';
import { ActivatedRoute, RouterModule } from '@angular/router';
import { environment } from '../../../environments/environment';
import { MatTabsModule } from '@angular/material/tabs';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { Chart, registerables } from 'chart.js';

Chart.register(...registerables);

@Component({
  selector: 'app-report',
  standalone: true,
  imports: [CommonModule, SidebarComponent, RouterModule, MatTabsModule, MatIconModule, MatProgressSpinnerModule, MatSnackBarModule],
  template: `
    <div class="flex h-screen bg-slate-100 dark:bg-slate-900 transition-colors duration-300 relative">
      <!-- Full-screen Loading Overlay -->
      <div *ngIf="isLoading" class="absolute inset-0 z-[100] bg-slate-900/60 backdrop-blur-sm flex flex-col items-center justify-center text-white">
        <mat-spinner diameter="50" color="primary"></mat-spinner>
        <p class="mt-4 font-black uppercase tracking-widest text-sm animate-pulse">Traitement en cours...</p>
      </div>

      <app-sidebar></app-sidebar>

      <main class="flex-1 ml-64 overflow-auto p-8">
        <header class="flex justify-between items-center mb-8">
          <div>
            <h2 class="text-3xl font-bold text-slate-800 dark:text-white">Rapport d'Audit SOC</h2>
            <p class="text-slate-500 dark:text-slate-400 text-sm">Analyse détaillée et recommandations de sécurité</p>
          </div>
          <div class="flex gap-3">
            <button (click)="sendEmail()" [disabled]="!analysis"
                    class="bg-slate-800 dark:bg-slate-700 text-white px-6 py-2 rounded-lg hover:bg-slate-900 transition disabled:opacity-50 flex items-center gap-2">
              <i class="fas fa-envelope"></i>
              Envoyer par Email
            </button>
            <button (click)="exportToPdf()" [disabled]="!analysis"
                    class="bg-indigo-600 text-white px-6 py-2 rounded-lg hover:bg-indigo-700 transition disabled:opacity-50 shadow-indigo flex items-center gap-2">
              <i class="fas fa-file-pdf"></i>
              Exporter en PDF
            </button>
          </div>
        </header>

        <div *ngIf="loading" class="flex flex-col items-center justify-center p-20 text-slate-400">
          <i class="fas fa-circle-notch fa-spin text-4xl mb-4 text-indigo-500"></i>
          <p class="font-bold">Génération du rapport en cours...</p>
        </div>

        <div *ngIf="!loading && !analysis" class="text-center p-20 bg-white dark:bg-slate-800 rounded-2xl shadow-card border border-slate-100 dark:border-slate-700">
          <div class="w-20 h-20 bg-slate-50 dark:bg-slate-700 rounded-full flex items-center justify-center mx-auto mb-6 text-slate-300">
            <i class="fas fa-file-invoice text-4xl"></i>
          </div>
          <h3 class="text-xl font-bold text-slate-800 dark:text-white mb-2">Aucun Rapport Sélectionné</h3>
          <p class="text-slate-500 dark:text-slate-400 mb-6">Veuillez choisir une analyse dans l'historique pour visualiser son rapport.</p>
          <a routerLink="/history" class="bg-indigo-600 text-white px-8 py-3 rounded-xl font-bold hover:bg-indigo-700 transition shadow-indigo">
            Consulter l'Historique
          </a>
        </div>

        <div *ngIf="analysis" class="space-y-8 max-w-6xl mx-auto">
          <!-- 1. File Metadata Section -->
          <div class="bg-white dark:bg-slate-800 rounded-2xl shadow-card p-6 border border-slate-200 dark:border-slate-700 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 items-center">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 bg-indigo-100 dark:bg-indigo-900/30 rounded-xl flex items-center justify-center text-indigo-600 dark:text-indigo-400">
                <i class="fas fa-file-alt text-xl"></i>
              </div>
              <div class="overflow-hidden">
                <p class="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Fichier Analysé</p>
                <p class="text-sm font-mono text-slate-700 dark:text-slate-300 truncate mt-1 bg-slate-50 dark:bg-slate-900/50 px-2 py-1 rounded" [title]="analysis.source_path">
                  {{ analysis.source_path || 'N/A' }}
                </p>
              </div>
            </div>

            <div class="flex items-center gap-4 pl-4 border-l border-slate-100 dark:border-slate-700">
              <div class="w-10 h-10 bg-emerald-100 dark:bg-emerald-900/30 rounded-lg flex items-center justify-center text-emerald-600 dark:text-emerald-400">
                <i class="fas fa-calendar-check"></i>
              </div>
              <div>
                <p class="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Date de l'Analyse</p>
                <p class="text-sm font-black text-slate-800 dark:text-white mt-1">{{ formatCreationDate(analysis.created_at) }}</p>
              </div>
            </div>

            <div class="flex items-center gap-4 pl-4 border-l border-slate-100 dark:border-slate-700">
              <div class="w-10 h-10 bg-amber-100 dark:bg-amber-900/30 rounded-lg flex items-center justify-center text-amber-600 dark:text-amber-400">
                <i class="fas fa-network-wired"></i>
              </div>
              <div>
                <p class="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Source des Logs</p>
                <p class="text-sm font-black text-indigo-500 dark:text-indigo-400 mt-1">
                  {{ analysis.source_type === 'SSH' ? analysis.server_ip : 'Hôte Local' }}
                </p>
              </div>
            </div>

            <div class="flex items-center justify-end gap-6 pl-4 border-l border-slate-100 dark:border-slate-700">
              <div class="text-right">
                <p class="text-[10px] font-bold text-slate-400 uppercase tracking-widest">ID Rapport</p>
                <p class="text-lg font-black text-indigo-600 dark:text-indigo-400">#{{ analysis.id }}</p>
              </div>
              <div class="flex flex-col items-end">
                <span class="px-3 py-1 bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300 text-[9px] font-black rounded-full border border-slate-200 dark:border-slate-600 uppercase tracking-tighter">
                  {{ analysis.source_type }}
                </span>
              </div>
            </div>
          </div>

          <div class="grid grid-cols-12 gap-8">
            <!-- 2. Log Distribution Chart -->
            <div class="col-span-12 lg:col-span-4 bg-white dark:bg-slate-800 rounded-2xl shadow-card p-6 border border-slate-200 dark:border-slate-700 flex flex-col">
              <h3 class="font-bold text-slate-800 dark:text-white flex items-center gap-2 mb-6">
                <i class="fas fa-chart-pie text-indigo-600"></i>
                Distribution des Logs
              </h3>
              <div class="flex-1 flex items-center justify-center min-h-[250px] relative">
                <canvas #logChart></canvas>
              </div>
              <div class="grid grid-cols-3 gap-2 mt-6">
                <div class="text-center">
                  <p class="text-[10px] font-bold text-red-500 uppercase">Errors</p>
                  <p class="text-lg font-bold dark:text-white">{{ analysis.stats.errors }}</p>
                </div>
                <div class="text-center">
                  <p class="text-[10px] font-bold text-amber-500 uppercase">Warnings</p>
                  <p class="text-lg font-bold dark:text-white">{{ analysis.stats.warnings }}</p>
                </div>
                <div class="text-center">
                  <p class="text-[10px] font-bold text-indigo-500 uppercase">Info</p>
                  <p class="text-lg font-bold dark:text-white">{{ analysis.stats.info }}</p>
                </div>
              </div>
            </div>

            <!-- Summary Stats -->
            <div class="col-span-12 lg:col-span-8 grid grid-cols-2 gap-6">
              <div class="bg-white dark:bg-slate-800 rounded-2xl shadow-card p-6 border border-slate-200 dark:border-slate-700 flex items-center gap-8">
                <!-- Circular Score -->
                <div class="relative w-32 h-32 flex items-center justify-center">
                  <svg class="w-full h-full transform -rotate-90">
                    <circle cx="64" cy="64" r="58" stroke="currentColor" stroke-width="8" fill="transparent"
                            class="text-slate-100 dark:text-slate-700" />
                    <circle cx="64" cy="64" r="58" stroke="currentColor" stroke-width="8" fill="transparent"
                            [attr.stroke-dasharray]="364.4"
                            [attr.stroke-dashoffset]="364.4 - (364.4 * analysis.ai_score / 100)"
                            [class.text-red-500]="analysis.ai_score < 50"
                            [class.text-amber-500]="analysis.ai_score >= 50 && analysis.ai_score < 80"
                            [class.text-emerald-500]="analysis.ai_score >= 80"
                            stroke-linecap="round" class="transition-all duration-1000 ease-out" />
                  </svg>
                  <div class="absolute flex flex-col items-center">
                    <span class="text-3xl font-black dark:text-white">{{ analysis.ai_score }}</span>
                    <span class="text-[8px] font-bold text-slate-400 uppercase tracking-widest">Score IA</span>
                  </div>
                </div>
                
                <div class="flex-1 space-y-4">
                  <div>
                    <p class="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">Statut de Sécurité</p>
                    <div [class]="getSecurityBadgeClass(analysis.ai_status)">
                      <i class="fas fa-shield-alt mr-2"></i>
                      {{ analysis.ai_status || 'Inconnu' }}
                    </div>
                  </div>
                  <p class="text-xs text-slate-500 leading-relaxed italic">
                    "{{ analysis.meta?.ai_insights || 'Analyse heuristique complétée avec succès.' | slice:0:100 }}..."
                  </p>
                </div>
              </div>

              <div class="bg-white dark:bg-slate-800 rounded-2xl shadow-card p-6 border border-slate-200 dark:border-slate-700">
                <p class="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-6">Indicateurs de Performance</p>
                <div class="grid grid-cols-1 gap-4">
                  <div class="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-900/50 rounded-xl border border-slate-100 dark:border-slate-700">
                    <div class="flex items-center gap-3">
                      <div class="p-2 bg-red-100 dark:bg-red-900/20 text-red-600 dark:text-red-400 rounded-lg">
                        <mat-icon class="text-sm">security</mat-icon>
                      </div>
                      <span class="text-sm font-medium text-slate-600 dark:text-slate-400">Menaces IA</span>
                    </div>
                    <span class="text-lg font-black text-red-600">{{ analysis.ai_menaces || 0 }}</span>
                  </div>
                  <div class="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-900/50 rounded-xl border border-slate-100 dark:border-slate-700">
                    <div class="flex items-center gap-3">
                      <div class="p-2 bg-indigo-100 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 rounded-lg">
                        <mat-icon class="text-sm">analytics</mat-icon>
                      </div>
                      <span class="text-sm font-medium text-slate-600 dark:text-slate-400">Logs Traités</span>
                    </div>
                    <span class="text-lg font-black text-indigo-600">{{ analysis.stats.total || 0 }}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- 3. Intelligent Log Aggregation -->
          <div class="bg-white dark:bg-slate-800 rounded-2xl shadow-card overflow-hidden border border-slate-200 dark:border-slate-700">
            <div class="p-6 bg-slate-50 dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-700 flex justify-between items-center">
              <h3 class="font-bold text-slate-800 dark:text-white flex items-center gap-2">
                <i class="fas fa-layer-group text-indigo-600"></i>
                Agrégation Intelligente des Logs (≥ 5x)
              </h3>
              <span class="text-[10px] font-bold bg-indigo-100 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 px-3 py-1 rounded-full border border-indigo-200 dark:border-indigo-800">
                {{ totalAggregatedCount }} Logs Identifiés
              </span>
            </div>
            
            <mat-tab-group class="custom-tabs" animationDuration="0ms">
              <mat-tab>
                <ng-template mat-tab-label>
                  <div class="flex items-center gap-2 text-red-600 font-bold px-4">
                    <i class="fas fa-exclamation-circle"></i>
                    ERRORS ({{ aggregatedLogs.error.length }})
                  </div>
                </ng-template>
                <div class="p-0">
                  <ng-container *ngTemplateOutlet="logTable; context: { logs: aggregatedLogs.error }"></ng-container>
                </div>
              </mat-tab>
              <mat-tab>
                <ng-template mat-tab-label>
                  <div class="flex items-center gap-2 text-amber-600 font-bold px-4">
                    <i class="fas fa-exclamation-triangle"></i>
                    WARNINGS ({{ aggregatedLogs.warning.length }})
                  </div>
                </ng-template>
                <div class="p-0">
                  <ng-container *ngTemplateOutlet="logTable; context: { logs: aggregatedLogs.warning }"></ng-container>
                </div>
              </mat-tab>
              <mat-tab>
                <ng-template mat-tab-label>
                  <div class="flex items-center gap-2 text-indigo-600 font-bold px-4">
                    <i class="fas fa-info-circle"></i>
                    INFO ({{ aggregatedLogs.info.length }})
                  </div>
                </ng-template>
                <div class="p-0">
                  <ng-container *ngTemplateOutlet="logTable; context: { logs: aggregatedLogs.info }"></ng-container>
                </div>
              </mat-tab>
            </mat-tab-group>

            <ng-template #logTable let-logs="logs">
              <div *ngIf="logs.length === 0" class="p-12 text-center text-slate-400 italic">
                Aucun log récurrent (≥ 5x) trouvé dans cette catégorie.
              </div>
              <table *ngIf="logs.length > 0" class="w-full text-left text-sm">
                <thead class="bg-slate-50/50 dark:bg-slate-900/30 text-slate-500 uppercase text-[10px] font-bold">
                  <tr>
                    <th class="px-6 py-3 w-32">Occurrence</th>
                    <th class="px-6 py-3">Message du Log</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-100 dark:divide-slate-700">
                  <tr *ngFor="let log of logs" class="hover:bg-slate-50 dark:hover:bg-slate-900/30 transition">
                    <td class="px-6 py-4">
                      <span class="px-2 py-1 bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-md font-black text-xs border border-slate-200 dark:border-slate-600">
                        {{ log.count }}x
                      </span>
                    </td>
                    <td class="px-6 py-4 font-mono text-xs text-slate-600 dark:text-slate-400 break-all">{{ log.message }}</td>
                  </tr>
                </tbody>
              </table>
            </ng-template>
          </div>

          <!-- 4. Expert Authentication Footer -->
          <div class="flex justify-end pt-12 pb-8">
            <div class="bg-white dark:bg-slate-800 p-6 rounded-2xl border border-slate-200 dark:border-slate-700 shadow-xl flex items-center gap-8">
              <div class="text-right space-y-2">
                <div>
                  <p class="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">Expert Analyste SOC</p>
                  <p class="text-xl font-black text-slate-800 dark:text-white">{{ expertName }}</p>
                  <p class="text-sm text-indigo-500 font-medium">{{ expertEmail }}</p>
                </div>
                <div class="flex justify-end gap-2">
                  <span class="px-2 py-1 bg-emerald-50 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400 text-[8px] font-black uppercase tracking-widest rounded border border-emerald-100 dark:border-emerald-800">
                    Certifié SOC-L3
                  </span>
                </div>
              </div>
              <div class="relative group">
                <div class="absolute -inset-1 bg-gradient-to-r from-indigo-500 to-purple-500 rounded-xl blur opacity-25 group-hover:opacity-50 transition duration-1000"></div>
                <div class="relative w-28 h-28 bg-white dark:bg-slate-900 p-2 rounded-xl border border-slate-200 dark:border-slate-700 shadow-inner flex items-center justify-center overflow-hidden">
                  <img *ngIf="qrCodeBase64" [src]="qrCodeBase64" class="w-full h-full object-contain transform scale-90 group-hover:scale-100 transition duration-500" alt="QR Code Expert">
                  <div *ngIf="!qrCodeBase64" class="text-[8px] text-slate-400 font-bold uppercase text-center">
                    <i class="fas fa-qrcode text-2xl mb-2 block opacity-20"></i>
                    Génération...
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  `,
  styles: [`
    :host ::ng-deep {
      .mat-mdc-tab-group {
        --mdc-tab-indicator-active-indicator-color: #4f46e5;
        --mat-tab-header-active-label-text-color: #4f46e5;
        --mat-tab-header-inactive-label-text-color: #64748b;
      }
      .dark .mat-mdc-tab-group {
        --mat-tab-header-inactive-label-text-color: #94a3b8;
        background: transparent;
      }
      .mat-mdc-tab-header {
        border-bottom: 1px solid #e2e8f0;
      }
      .dark .mat-mdc-tab-header {
        border-bottom-color: #334155;
      }
    }
  `]
})
export class ReportComponent implements OnInit, AfterViewInit {
  @ViewChild('logChart') logChartCanvas!: ElementRef;

  analysis: Analysis | null = null;
  loading = false;
  isLoading = false;
  
  // Aggrégation intelligente
  aggregatedLogs: {
    error: { count: number; message: string }[];
    warning: { count: number; message: string }[];
    info: { count: number; message: string }[];
  } = { error: [], warning: [], info: [] };
  
  totalAggregatedCount = 0;
  
  expertName = '';
  expertEmail = '';
  qrCodeBase64: string | null = null;
  chart: Chart | null = null;

  private apiUrl = environment.apiUrl;

  constructor(
    private logService: LogService,
    private notify: NotificationService,
    private route: ActivatedRoute,
    private http: HttpClient,
    private snackBar: MatSnackBar
  ) {}

  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      const id = params['id'];
      if (id) {
        this.fetchAnalysisDetails(+id);
      }
    });
    this.loadExpertInfo();
    this.loadQRCode();
  }

  ngAfterViewInit(): void {
    if (this.analysis) {
      this.initChart();
    }
  }

  loadExpertInfo(): void {
    this.http.get<{ firstName: string; lastName: string; username: string; email: string }>(`${this.apiUrl}/profile`).subscribe({
      next: (res) => {
        this.expertName = [res.firstName, res.lastName].filter(Boolean).join(' ') || res.username;
        this.expertEmail = res.email;
      }
    });
  }

  loadQRCode(): void {
    this.http.get<any>(`${this.apiUrl}/generate-qr`).subscribe({
      next: (res) => {
        if (res.status === 'success') {
          this.qrCodeBase64 = res.qr_code;
        }
      }
    });
  }

  fetchAnalysisDetails(id: number): void {
    this.loading = true;
    this.logService.getAnalysis(id).subscribe({
      next: (data) => {
        this.analysis = data.analysis;
        this.processAggregatedLogs();
        this.loading = false;
        setTimeout(() => this.initChart(), 0);
      },
      error: (err) => {
        console.error('Error fetching analysis details:', err);
        this.loading = false;
        this.notify.error('Erreur lors du chargement du rapport.');
      }
    });
  }

  processAggregatedLogs(): void {
    if (!this.analysis || !this.analysis.segments) return;
    
    this.aggregatedLogs = { error: [], warning: [], info: [] };
    this.totalAggregatedCount = 0;

    const processLevel = (level: 'error' | 'warning' | 'info', data: any) => {
      const logs = Array.isArray(data) ? data : [];
      const counts: { [key: string]: number } = {};
      
      logs.forEach((log: any) => {
        const msg = typeof log === 'string' ? log : (log.message || '');
        if (msg) counts[msg] = (counts[msg] || 0) + 1;
      });

      const aggregated = Object.entries(counts)
        .map(([message, count]) => ({ message, count }))
        .filter(item => item.count >= 5)
        .sort((a, b) => b.count - a.count);
      
      this.aggregatedLogs[level] = aggregated;
      this.totalAggregatedCount += aggregated.length;
    };

    processLevel('error', this.analysis.segments.critique || this.analysis.segments.error);
    processLevel('warning', this.analysis.segments.avertissement || this.analysis.segments.warning);
    processLevel('info', this.analysis.segments.info);
  }

  initChart(): void {
    if (!this.analysis || !this.logChartCanvas) return;
    
    if (this.chart) {
      this.chart.destroy();
    }

    const ctx = this.logChartCanvas.nativeElement.getContext('2d');
    const stats = this.analysis.stats;
    
    this.chart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Errors', 'Warnings', 'Info'],
        datasets: [{
          data: [stats.errors, stats.warnings, stats.info],
          backgroundColor: ['#ef4444', '#f59e0b', '#6366f1'],
          borderWidth: 0,
          hoverOffset: 10
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            callbacks: {
              label: (context) => {
                const total = stats.errors + stats.warnings + stats.info;
                const value = context.raw as number;
                const percentage = ((value / total) * 100).toFixed(1);
                return `${context.label}: ${value} (${percentage}%)`;
              }
            }
          }
        },
        cutout: '70%'
      }
    });
  }

  formatCreationDate(dateStr: string): string {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    const d = date.getDate().toString().padStart(2, '0');
    const m = (date.getMonth() + 1).toString().padStart(2, '0');
    const y = date.getFullYear();
    const h = date.getHours().toString().padStart(2, '0');
    const min = date.getMinutes().toString().padStart(2, '0');
    return `${d}/${m}/${y} ${h}:${min}`;
  }

  async sendEmail(): Promise<void> {
    if (!this.analysis) return;
    
    const email = await this.notify.prompt(
      'Envoi du rapport',
      'Entrez l\'adresse email du destinataire',
      'text'
    );

    if (email) {
      this.isLoading = true;
      this.logService.sendReportEmail({
        analysis_id: this.analysis.id,
        recipient: email
      }).subscribe({
        next: () => {
          this.isLoading = false;
          this.snackBar.open('Rapport envoyé avec succès !', 'Fermer', { duration: 5000 });
        },
        error: (err) => {
          this.isLoading = false;
          this.snackBar.open('Erreur lors de l\'envoi du rapport.', 'Fermer', { duration: 5000, panelClass: ['error-snackbar'] });
        }
      });
    }
  }

  exportToPdf(): void {
    if (!this.analysis) return;
    
    this.isLoading = true;
    this.logService.downloadAnalysisPdf(this.analysis.id).subscribe({
      next: (blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Rapport_Audit_${this.analysis?.id}.pdf`;
        a.click();
        window.URL.revokeObjectURL(url);
        this.isLoading = false;
        this.snackBar.open('PDF téléchargé avec succès !', 'Fermer', { duration: 3000 });
      },
      error: (err) => {
        this.isLoading = false;
        this.snackBar.open('Erreur lors du téléchargement du PDF.', 'Fermer', { duration: 5000 });
      }
    });
  }

  getSecurityBadgeClass(status: string | null): string {
    const baseClass = "px-4 py-2 rounded-xl font-bold text-xs uppercase tracking-widest shadow-sm border";
    if (!status) return `${baseClass} bg-slate-100 text-slate-600 border-slate-200`;
    
    const s = status.toLowerCase();
    if (s.includes('critique') || s.includes('danger')) return `${baseClass} bg-red-100 text-red-700 border-red-200`;
    if (s.includes('attention') || s.includes('warning')) return `${baseClass} bg-amber-100 text-amber-700 border-amber-200`;
    return `${baseClass} bg-emerald-100 text-emerald-700 border-emerald-200`;
  }
}


