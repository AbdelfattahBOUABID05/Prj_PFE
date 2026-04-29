import { Component, OnInit, AfterViewInit, ViewChild, ElementRef, ChangeDetectorRef } from '@angular/core';
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
  templateUrl: './report.component.html',
  styleUrls: ['./report.component.css']
})
export class ReportComponent implements OnInit, AfterViewInit {
  @ViewChild('logChart') logChartCanvas!: ElementRef;

  analysis: Analysis | null = null;
  loading = false;
  isLoading = false;

  // Logs filtrés par catégorie
  errorLogs: any[] = [];
  warningLogs: any[] = [];
  infoLogs: any[] = [];
  
  // Aggrégation intelligente
  aggregatedLogs: {
    error: { count: number; message: string }[];
    warning: { count: number; message: string }[];
    info: { count: number; message: string }[];
  } = { error: [], warning: [], info: [] };
  
  totalAggregatedCount = 0;
  showAggregatedLogs = false;
  
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
    private snackBar: MatSnackBar,
    private cdr: ChangeDetectorRef
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
        this.filterLogs();
        this.processAggregatedLogs();
        this.loading = false;
        this.cdr.detectChanges(); // Force UI update
        setTimeout(() => this.initChart(), 0);
      },
      error: (err) => {
        console.error('Error fetching analysis details:', err);
        this.loading = false;
        this.notify.error('Erreur lors du chargement du rapport.');
      }
    });
  }

  filterLogs(): void {
    if (!this.analysis) return;

    this.errorLogs = [];
    this.warningLogs = [];
    this.infoLogs = [];

    // Priorité 1 : Liste plate all_logs (plus flexible pour le filtrage côté client)
    const allLogs = this.analysis.meta?.all_logs || [];
    
    if (allLogs.length > 0) {
      allLogs.forEach((log: any) => {
        if (!log) return;
        
        // Extraction du niveau de log (insensible à la casse)
        const level = (log.level || log.type || 'info').toLowerCase();
        
        if (level.includes('error') || level.includes('critique') || level.includes('critical') || level.includes('high')) {
          this.errorLogs.push(log);
        } else if (level.includes('warning') || level.includes('avertissement') || level.includes('medium') || level.includes('warn')) {
          this.warningLogs.push(log);
        } else {
          this.infoLogs.push(log);
        }
      });
    } 
    
    // Priorité 2 : Segments pré-filtrés par le backend (si all_logs est vide)
    if (this.errorLogs.length === 0 && this.warningLogs.length === 0 && this.infoLogs.length === 0 && this.analysis.segments) {
      this.errorLogs = this.analysis.segments.critique || this.analysis.segments.critical || this.analysis.segments.error || this.analysis.segments.errors || [];
      this.warningLogs = this.analysis.segments.avertissement || this.analysis.segments.warning || this.analysis.segments.warnings || [];
      this.infoLogs = this.analysis.segments.info || [];
    }

    // Sécurité : S'assurer que ce sont bien des tableaux
    this.errorLogs = Array.isArray(this.errorLogs) ? this.errorLogs : [];
    this.warningLogs = Array.isArray(this.warningLogs) ? this.warningLogs : [];
    this.infoLogs = Array.isArray(this.infoLogs) ? this.infoLogs : [];

    console.log(`Logs filtrés : ${this.errorLogs.length} Errors, ${this.warningLogs.length} Warnings, ${this.infoLogs.length} Infos`);
    this.cdr.detectChanges();
  }

  processAggregatedLogs(): void {
    if (!this.analysis) return;
    
    this.aggregatedLogs = { error: [], warning: [], info: [] };
    this.totalAggregatedCount = 0;

    const processLevel = (level: 'error' | 'warning' | 'info', logs: any[]) => {
      const counts: { [key: string]: number } = {};
      
      logs.forEach((log: any) => {
        const msg = typeof log === 'string' ? log : (log.message || log.raw || '');
        if (msg) counts[msg] = (counts[msg] || 0) + 1;
      });

      const aggregated = Object.entries(counts)
        .map(([message, count]) => ({ message, count }))
        .filter(item => item.count >= 5)
        .sort((a, b) => b.count - a.count);
      
      this.aggregatedLogs[level] = aggregated;
      this.totalAggregatedCount += aggregated.length;
    };

    processLevel('error', this.errorLogs);
    processLevel('warning', this.warningLogs);
    processLevel('info', this.infoLogs);
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
    const baseClass = "px-4 py-2 rounded-xl font-black text-xs uppercase tracking-widest shadow-lg border transition-all duration-300";
    if (!status) return `${baseClass} bg-slate-500/20 text-slate-400 border-slate-500/20`;
    
    const s = status.toLowerCase();
    if (s.includes('critique') || s.includes('danger') || s.includes('error')) return `${baseClass} bg-rose-500/20 text-rose-400 border-rose-500/20`;
    if (s.includes('attention') || s.includes('warning') || s.includes('moyen')) return `${baseClass} bg-amber-500/20 text-amber-400 border-amber-500/20`;
    return `${baseClass} bg-emerald-500/20 text-emerald-400 border-emerald-500/20`;
  }

  getLogMessage(log: any): string {
    if (!log) return '';
    if (typeof log === 'string') return log;
    return log.message || log.raw || log.content || JSON.stringify(log);
  }
}


