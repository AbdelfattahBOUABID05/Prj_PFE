import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { SidebarComponent } from '../sidebar/sidebar.component';
import { LogService, Analysis } from '../../services/log.service';
import { NotificationService } from '../../services/notification.service';
import { ActivatedRoute, RouterModule } from '@angular/router';
import { environment } from '../../../environments/environment';

@Component({
  selector: 'app-report',
  standalone: true,
  imports: [CommonModule, SidebarComponent, RouterModule],
  template: `
    <div class="flex h-screen bg-slate-100">
      <app-sidebar></app-sidebar>

      <main class="flex-1 ml-64 overflow-auto p-8">
        <header class="flex justify-between items-center mb-8">
          <div>
            <h2 class="text-3xl font-bold text-slate-800">Rapport d'Audit SOC</h2>
            <p class="text-slate-500 text-sm">Analyse détaillée et recommandations de sécurité</p>
          </div>
          <div class="flex gap-3">
            <button (click)="sendEmail()" [disabled]="!analysis"
                    class="bg-slate-800 text-white px-6 py-2 rounded-lg hover:bg-slate-900 transition disabled:opacity-50 flex items-center gap-2">
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
          <i class="fas fa-circle-notch fa-spin text-4xl mb-4"></i>
          <p class="font-bold">Génération du rapport en cours...</p>
        </div>

        <div *ngIf="!loading && !analysis" class="text-center p-20 bg-white rounded-2xl shadow-card border border-slate-100">
          <div class="w-20 h-20 bg-slate-50 rounded-full flex items-center justify-center mx-auto mb-6 text-slate-300">
            <i class="fas fa-file-invoice text-4xl"></i>
          </div>
          <h3 class="text-xl font-bold text-slate-800 mb-2">Aucun Rapport Sélectionné</h3>
          <p class="text-slate-500 mb-6">Veuillez choisir une analyse dans l'historique pour visualiser son rapport.</p>
          <a routerLink="/history" class="bg-indigo-600 text-white px-8 py-3 rounded-xl font-bold hover:bg-indigo-700 transition shadow-indigo">
            Consulter l'Historique
          </a>
        </div>

        <div *ngIf="analysis" class="space-y-8 max-w-5xl">
          <div class="bg-white rounded-2xl shadow-card p-8 border border-slate-200">
            <div class="flex justify-between items-start mb-8 pb-6 border-b border-slate-100">
              <div class="space-y-1">
                <h3 class="text-2xl font-bold text-slate-800">Détails de l'Analyse #{{ analysis.id }}</h3>
                <div class="flex items-center gap-4 text-sm text-slate-500">
                  <span class="flex items-center gap-2"><i class="fas fa-calendar-alt text-indigo-500"></i> {{ formatCreationDate(analysis.created_at) }}</span>
                  <span class="flex items-center gap-2"><i class="fas fa-server text-indigo-500"></i> {{ analysis.server_ip || 'Fichier Local' }}</span>
                </div>
              </div>
              <div [class]="getSecurityBadgeClass(analysis.ai_status)">
                <i class="fas fa-shield-alt mr-2"></i>
                {{ analysis.ai_status || 'Inconnu' }}
              </div>
            </div>

            <div class="grid grid-cols-4 gap-6">
              <div class="p-4 bg-slate-50 rounded-xl border border-slate-100 text-center">
                <p class="text-[10px] font-bold text-slate-400 uppercase mb-1">Score Sécurité</p>
                <p class="text-2xl font-bold" [class.text-red-600]="analysis.ai_score < 50" [class.text-emerald-600]="analysis.ai_score >= 80" [class.text-amber-600]="analysis.ai_score >= 50 && analysis.ai_score < 80">
                  {{ analysis.ai_score }}/100
                </p>
              </div>
              <div class="p-4 bg-slate-50 rounded-xl border border-slate-100 text-center">
                <p class="text-[10px] font-bold text-slate-400 uppercase mb-1">Menaces IA</p>
                <p class="text-2xl font-bold text-red-600">{{ analysis.ai_menaces || 0 }}</p>
              </div>
              <div class="p-4 bg-slate-50 rounded-xl border border-slate-100 text-center">
                <p class="text-[10px] font-bold text-slate-400 uppercase mb-1">Lignes Analysées</p>
                <p class="text-2xl font-bold text-indigo-600">{{ analysis.stats?.total || 0 }}</p>
              </div>
              <div class="p-4 bg-slate-50 rounded-xl border border-slate-100 text-center">
                <p class="text-[10px] font-bold text-slate-400 uppercase mb-1">Source</p>
                <p class="text-2xl font-bold text-slate-700 uppercase">{{ analysis.source_type }}</p>
              </div>
            </div>
          </div>

          <div class="bg-white rounded-2xl shadow-card overflow-hidden border border-slate-200">
            <div class="p-6 bg-slate-50 border-b border-slate-200">
              <h3 class="font-bold text-slate-800 flex items-center gap-2">
                <i class="fas fa-list-ol text-indigo-600"></i>
                Top 10 des Logs Récurrents
              </h3>
            </div>
            <div class="p-0">
              <table class="w-full text-left text-sm">
                <thead class="bg-slate-50/50 text-slate-500 uppercase text-[10px] font-bold">
                  <tr>
                    <th class="px-6 py-3">Occurrence</th>
                    <th class="px-6 py-3">Message du Log</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-100">
                  <tr *ngFor="let log of recurringLogs" class="hover:bg-slate-50 transition">
                    <td class="px-6 py-4">
                      <span class="px-2 py-1 bg-indigo-100 text-indigo-700 rounded-md font-bold">{{ log.count }}x</span>
                    </td>
                    <td class="px-6 py-4 font-mono text-xs text-slate-600">{{ log.message }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="flex justify-end pt-8">
            <div class="text-right space-y-4">
              <div class="space-y-1">
                <p class="text-xs font-bold text-slate-400 uppercase tracking-widest">Expert Analyste SOC</p>
                <p class="text-lg font-bold text-slate-800">{{ expertName }}</p>
                <p class="text-sm text-slate-500">{{ expertEmail }}</p>
              </div>
              <div class="h-24 flex justify-end">
                <img *ngIf="signatureUrl" [src]="signatureUrl" class="h-full object-contain filter contrast-125">
                <div *ngIf="!signatureUrl" class="h-full w-48 border border-dashed border-slate-200 rounded-lg flex items-center justify-center text-slate-300 italic text-xs">
                  Signature en attente
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  `
})
export class ReportComponent implements OnInit {
  analysis: Analysis | null = null;
  loading = false;
  recurringLogs: { count: number; message: string }[] = [];
  expertName = '';
  expertEmail = '';
  signatureUrl = '';

  private apiUrl = environment.apiUrl;

  constructor(
    private logService: LogService,
    private notify: NotificationService,
    private route: ActivatedRoute,
    private http: HttpClient
  ) {}

  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      const id = params['id'];
      if (id) {
        this.fetchAnalysisDetails(+id);
      }
    });
    this.loadExpertInfo();
  }

  loadExpertInfo(): void {
    this.http.get<{ firstName: string; lastName: string; username: string; email: string; signature_path?: string }>(`${this.apiUrl}/profile`).subscribe({
      next: (res) => {
        this.expertName = [res.firstName, res.lastName].filter(Boolean).join(' ') || res.username;
        this.expertEmail = res.email;
        if (res.signature_path) {
          this.signatureUrl = `${this.apiUrl}/static/${res.signature_path}`;
        }
      }
    });
  }

  fetchAnalysisDetails(id: number): void {
    this.loading = true;
    this.logService.getAnalysis(id).subscribe({
      next: (data) => {
        this.analysis = data.analysis;
        this.processRecurringLogs();
        this.loading = false;
      },
      error: (err) => {
        console.error('Error fetching analysis details:', err);
        this.loading = false;
        this.notify.error('Erreur lors du chargement du rapport.');
      }
    });
  }

  processRecurringLogs(): void {
    if (!this.analysis || !this.analysis.segments) return;
    
    const allLogs: string[] = [];
    Object.values(this.analysis.segments).forEach((levelLogs: any) => {
      if (Array.isArray(levelLogs)) {
        levelLogs.forEach((log: any) => allLogs.push(log.message || log));
      }
    });

    const counts: { [key: string]: number } = {};
    allLogs.forEach(msg => {
      counts[msg] = (counts[msg] || 0) + 1;
    });

    this.recurringLogs = Object.entries(counts)
      .map(([message, count]) => ({ message, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  formatCreationDate(dateStr: string): string {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleString('fr-FR', {
      day: '2-digit', month: 'long', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  }

  async sendEmail(): Promise<void> {
    if (!this.analysis) return;
    
    const email = await this.notify.prompt(
      'Envoi du rapport',
      'Entrez l\'adresse email du destinataire',
      'text'
    );

    if (email) {
      this.notify.info('Envoi de l\'email en cours...');
      this.logService.sendReportEmail({
        analysis_id: this.analysis.id,
        recipient: email
      }).subscribe({
        next: () => this.notify.success(`Rapport envoyé avec succès à ${email}`),
        error: (err) => this.notify.error('Erreur lors de l\'envoi du rapport.')
      });
    }
  }

  exportToPdf(): void {
    if (!this.analysis) return;
    
    this.notify.info('Génération du PDF...');
    this.logService.downloadAnalysisPdf(this.analysis.id).subscribe({
      next: (blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        if (this.analysis && this.analysis.id) {
            a.download = `Rapport_Audit_${this.analysis.id}.pdf`;
        } else {
            a.download = `Rapport_Audit_Analysis.pdf`;
}
        a.click();
        window.URL.revokeObjectURL(url);
        this.notify.success('PDF téléchargé avec succès.');
      },
      error: (err) => this.notify.error('Erreur lors du téléchargement du PDF.')
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
