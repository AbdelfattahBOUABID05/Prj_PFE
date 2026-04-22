import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { LogService, DashboardSummary, StatsResponse } from '../../services/log.service';
import { SidebarComponent } from '../sidebar/sidebar.component';
import { Chart, registerables } from 'chart.js';
import { NotificationService } from '../../services/notification.service';

Chart.register(...registerables);

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterModule, SidebarComponent, FormsModule],
  template: `
    <div class="flex h-screen bg-slate-100">
      <app-sidebar></app-sidebar>

      <main class="flex-1 ml-64 overflow-auto">
        <header class="bg-white border-b border-slate-200 px-8 py-4 flex justify-between items-center sticky top-0 z-10">
          <div>
            <h2 class="text-2xl font-bold text-slate-800">Tableau de bord</h2>
            <p class="text-slate-500 text-sm">Surveillance intelligente et visualisation avancée des menaces</p>
          </div>
          
          <div class="flex items-center gap-4 bg-slate-50 p-2 rounded-xl border border-slate-200">
            <div class="flex gap-1">
              <button (click)="loadStats('24h')"
                      [class.bg-white]="period === '24h'"
                      [class.shadow-sm]="period === '24h'"
                      [class.text-indigo-600]="period === '24h'"
                      class="px-3 py-1.5 rounded-lg text-slate-500 hover:text-indigo-600 text-xs font-bold transition">
                24h
              </button>
              <button (click)="loadStats('7d')"
                      [class.bg-white]="period === '7d'"
                      [class.shadow-sm]="period === '7d'"
                      [class.text-indigo-600]="period === '7d'"
                      class="px-3 py-1.5 rounded-lg text-slate-500 hover:text-indigo-600 text-xs font-bold transition">
                7J
              </button>
              <button (click)="loadStats('30d')"
                      [class.bg-white]="period === '30d'"
                      [class.shadow-sm]="period === '30d'"
                      [class.text-indigo-600]="period === '30d'"
                      class="px-3 py-1.5 rounded-lg text-slate-500 hover:text-indigo-600 text-xs font-bold transition">
                1M
              </button>
            </div>
            
            <div class="h-6 w-[1px] bg-slate-200"></div>
            
            <div class="flex items-center gap-2 px-2">
              <input type="date" [(ngModel)]="dateRange.start" (change)="onDateChange()"
                     class="bg-transparent border-none text-xs font-bold text-slate-600 outline-none">
              <span class="text-slate-400 text-xs">à</span>
              <input type="date" [(ngModel)]="dateRange.end" (change)="onDateChange()"
                     class="bg-transparent border-none text-xs font-bold text-slate-600 outline-none">
            </div>
          </div>
        </header>

        <!-- Stats Cards -->
        <div class="p-8 grid grid-cols-4 gap-6">
          <div class="stat-card p-6 border-b-4 border-indigo-500 bg-white rounded-xl shadow-sm">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-slate-500 text-xs font-bold uppercase tracking-wider">Serveurs</p>
                <p class="text-3xl font-bold text-slate-800 mt-1">{{ summary?.active_servers || 0 }}</p>
              </div>
              <div class="w-12 h-12 rounded-2xl bg-indigo-50 flex items-center justify-center text-indigo-600 shadow-sm">
                <i class="fas fa-server text-xl"></i>
              </div>
            </div>
          </div>

          <div class="stat-card p-6 border-b-4 border-emerald-500 bg-white rounded-xl shadow-sm">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-slate-500 text-xs font-bold uppercase tracking-wider">Audits Total</p>
                <p class="text-3xl font-bold text-slate-800 mt-1">{{ summary?.total_audits || 0 }}</p>
              </div>
              <div class="w-12 h-12 rounded-2xl bg-emerald-50 flex items-center justify-center text-emerald-600 shadow-sm">
                <i class="fas fa-shield-alt text-xl"></i>
              </div>
            </div>
          </div>

          <div class="stat-card p-6 border-b-4 border-red-500 bg-white rounded-xl shadow-sm">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-slate-500 text-xs font-bold uppercase tracking-wider">Menaces</p>
                <p class="text-3xl font-bold text-red-600 mt-1">{{ summary?.critical_threats || 0 }}</p>
              </div>
              <div class="w-12 h-12 rounded-2xl bg-red-50 flex items-center justify-center text-red-600 shadow-sm">
                <i class="fas fa-bug text-xl"></i>
              </div>
            </div>
          </div>

          <div class="stat-card p-6 border-b-4 border-indigo-500 bg-white rounded-xl shadow-sm">
            <div class="flex items-center justify-between">
              <div>
                <p class="text-slate-500 text-xs font-bold uppercase tracking-wider">Santé</p>
                <p class="text-3xl font-bold text-indigo-600 mt-1">{{ summary?.system_health || 100 }}%</p>
              </div>
              <div class="w-12 h-12 rounded-2xl bg-indigo-50 flex items-center justify-center text-indigo-600 shadow-sm">
                <i class="fas fa-heartbeat text-xl"></i>
              </div>
            </div>
          </div>
        </div>

        <!-- Main Charts Grid -->
        <div class="px-8 grid grid-cols-12 gap-6 mb-8">
          <!-- Activity Line Chart (Smooth) -->
          <div class="stat-card p-6 col-span-8 bg-white rounded-xl shadow-sm">
            <div class="flex justify-between items-center mb-6">
              <h3 class="font-bold text-slate-800">Activité des Logs (Smooth Line)</h3>
              <div class="flex gap-2">
                <span class="flex items-center gap-1 text-[10px] font-bold text-slate-400">
                  <span class="w-2 h-2 rounded-full bg-indigo-500"></span> Logs
                </span>
              </div>
            </div>
            <div class="h-80">
              <canvas id="activityLineChart"></canvas>
            </div>
          </div>

          <!-- Severity Pie Chart -->
          <div class="stat-card p-6 col-span-4 bg-white rounded-xl shadow-sm">
            <h3 class="font-bold text-slate-800 mb-6">Répartition des Alertes</h3>
            <div class="h-80 flex items-center justify-center">
              <canvas id="severityPieChart"></canvas>
            </div>
          </div>

          <!-- Time Series Line Chart avec Filtres -->
          <div class="stat-card p-6 col-span-12 bg-white rounded-xl shadow-sm">
            <div class="flex justify-between items-center mb-6">
              <h3 class="font-bold text-slate-800">Fréquence des Logs vs Temps</h3>
              <div class="flex gap-2">
                <button (click)="filterLogs('error')" 
                        [class.bg-red-500]="activeFilter === 'error'"
                        [class.text-white]="activeFilter === 'error'"
                        [class.shadow-red]="activeFilter === 'error'"
                        class="px-4 py-2 rounded-full text-[10px] font-bold uppercase transition border border-red-200 hover:bg-red-100">
                  Erreurs
                </button>
                <button (click)="filterLogs('warning')" 
                        [class.bg-amber-500]="activeFilter === 'warning'"
                        [class.text-white]="activeFilter === 'warning'"
                        class="px-4 py-2 rounded-full text-[10px] font-bold uppercase transition border border-amber-200 hover:bg-amber-100">
                  Avertissements
                </button>
                <button (click)="filterLogs('info')" 
                        [class.bg-blue-500]="activeFilter === 'info'"
                        [class.text-white]="activeFilter === 'info'"
                        class="px-4 py-2 rounded-full text-[10px] font-bold uppercase transition border border-blue-200 hover:bg-blue-100">
                  Infos
                </button>
                <button (click)="filterLogs('all')" 
                        [class.bg-indigo-500]="activeFilter === 'all'"
                        [class.text-white]="activeFilter === 'all'"
                        class="px-4 py-2 rounded-full text-[10px] font-bold uppercase transition border border-indigo-200 hover:bg-indigo-100">
                  Tout
                </button>
              </div>
            </div>
            <div class="h-72">
              <canvas id="timeSeriesLineChart"></canvas>
            </div>
            
            <!-- Log Details List (Filtered) -->
            <div class="mt-6 border-t border-slate-100 pt-4">
              <h4 class="text-xs font-bold text-slate-500 uppercase mb-3">Derniers logs - {{ getFilterLabel() }}</h4>
              <div class="max-h-48 overflow-y-auto space-y-2">
                <div *ngFor="let log of filteredLogs" 
                     class="flex items-center gap-3 p-2 rounded-lg hover:bg-slate-50 transition"
                     [class.bg-red-50]="log.level === 'ERROR'"
                     [class.bg-amber-50]="log.level === 'WARNING'"
                     [class.bg-blue-50]="log.level === 'INFO'">
                  <span class="text-[10px] font-mono text-slate-400 w-24">{{ log.timestamp }}</span>
                  <span [class]="'px-2 py-0.5 rounded text-[9px] font-bold uppercase ' + getLevelClass(log.level)">
                    {{ log.level }}
                  </span>
                  <span class="text-xs text-slate-600 truncate flex-1">{{ log.message }}</span>
                </div>
                <div *ngIf="filteredLogs.length === 0" class="text-center text-slate-400 text-xs py-4 italic">
                  Aucun log pour ce filtre.
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- AI Audit Section -->
        <div class="px-8 pb-8">
          <div class="stat-card p-8 bg-indigo-900 text-white border-none shadow-indigo-lg rounded-xl">
            <div class="flex items-center justify-between mb-6">
              <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-xl bg-indigo-500/20 flex items-center justify-center border border-indigo-400/30">
                  <i class="fas fa-robot text-indigo-300"></i>
                </div>
                <h3 class="text-xl font-bold">Analyse Prédictive IA</h3>
              </div>
              <span class="px-3 py-1 rounded-full bg-indigo-500/20 text-indigo-300 text-[10px] font-bold uppercase tracking-widest border border-indigo-400/20">
                SOC Intelligence
              </span>
            </div>
            <div id="aiSummary">
              <div class="grid grid-cols-2 gap-4">
                <div *ngFor="let point of auditPoints" class="flex items-start gap-3 p-4 bg-white/5 rounded-xl border border-white/5 hover:bg-white/10 transition cursor-default">
                  <i class="fas fa-check-circle text-indigo-400 mt-1"></i>
                  <span class="text-sm text-slate-300">{{ point }}</span>
                </div>
              </div>
              <div *ngIf="auditPoints.length === 0" class="text-center p-8 text-indigo-300/50 italic">
                Aucune donnée d'audit IA disponible pour cette période.
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  `
})
export class DashboardComponent implements OnInit {
  summary: DashboardSummary | null = null;
  period = '7d';
  dateRange = { start: '', end: '' };
  auditPoints: string[] = [];
  activeFilter: 'error' | 'warning' | 'info' | 'all' = 'all';
  
  private currentStatsData: StatsResponse | null = null;
  private activityLineChart: Chart | null = null;
  private pieChart: Chart | null = null;
  private timeSeriesChart: Chart | null = null;

  filteredLogs: { timestamp: string; level: string; message: string }[] = [];

  constructor(
    private logService: LogService,
    private notify: NotificationService
  ) {}

  ngOnInit(): void {
    const today = new Date();
    const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
    this.dateRange = {
      start: weekAgo.toISOString().split('T')[0],
      end: today.toISOString().split('T')[0]
    };
    this.loadDashboard();
    this.loadStats(this.period);
  }

  loadDashboard(): void {
    this.logService.getDashboard().subscribe({
      next: (data) => {
        if (data.status === 'success') {
          this.summary = data.summary;
          if (data.analysis_data?.meta?.audit_points) {
            this.auditPoints = data.analysis_data.meta.audit_points;
          }
        }
      },
      error: (err) => {
        console.error('Dashboard error:', err);
        this.notify.error('Erreur lors du chargement du tableau de bord.');
      }
    });
  }

  loadStats(period: string): void {
    this.period = period;
    this.logService.getStats(period).subscribe({
      next: (data) => {
        if (data.status === 'success') {
          this.currentStatsData = data;
          this.renderActivityLineChart(data);
          this.renderPieChart(data);
          this.renderTimeSeriesChart(data);
          this.applyFilter();
        }
      },
      error: (err) => {
        console.error('Stats error:', err);
        this.notify.error('Erreur lors du chargement des statistiques.');
      }
    });
  }

  onDateChange(): void {
    console.log('Date range changed:', this.dateRange);
  }

  filterLogs(type: 'error' | 'warning' | 'info' | 'all'): void {
    this.activeFilter = type;
    this.applyFilter();
  }

  getFilterLabel(): string {
    switch (this.activeFilter) {
      case 'error': return 'Erreurs';
      case 'warning': return 'Avertissements';
      case 'info': return 'Infos';
      default: return 'Tous les logs';
    }
  }

  getLevelClass(level: string): string {
    switch (level) {
      case 'ERROR': return 'bg-red-100 text-red-700';
      case 'WARNING': return 'bg-amber-100 text-amber-700';
      case 'INFO': return 'bg-blue-100 text-blue-700';
      default: return 'bg-slate-100 text-slate-600';
    }
  }

  private applyFilter(): void {
    if (!this.currentStatsData?.analysis_data?.segments) {
      this.filteredLogs = [];
      return;
    }

    const segments = this.currentStatsData.analysis_data.segments;
    const logs: { timestamp: string; level: string; message: string }[] = [];

    if (this.activeFilter === 'error' || this.activeFilter === 'all') {
      (segments['ERROR'] || []).forEach((l: any) => logs.push({ timestamp: l.timestamp || '', level: 'ERROR', message: l.message || l }));
    }
    if (this.activeFilter === 'warning' || this.activeFilter === 'all') {
      (segments['WARNING'] || []).forEach((l: any) => logs.push({ timestamp: l.timestamp || '', level: 'WARNING', message: l.message || l }));
    }
    if (this.activeFilter === 'info' || this.activeFilter === 'all') {
      (segments['INFO'] || []).forEach((l: any) => logs.push({ timestamp: l.timestamp || '', level: 'INFO', message: l.message || l }));
    }

    this.filteredLogs = logs.slice(0, 50);
  }

  private renderActivityLineChart(data: StatsResponse): void {
    const ctx = document.getElementById('activityLineChart') as HTMLCanvasElement;
    if (!ctx) return;
    if (this.activityLineChart) this.activityLineChart.destroy();

    this.activityLineChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels,
        datasets: [{
          label: 'Logs',
          data: data.info,
          borderColor: '#6366f1',
          backgroundColor: 'rgba(99, 102, 241, 0.1)',
          fill: true,
          tension: 0.4,
          pointRadius: 4,
          pointHoverRadius: 6,
          pointBackgroundColor: '#6366f1',
          pointBorderColor: '#ffffff',
          pointBorderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(0,0,0,0.03)' },
            ticks: { font: { size: 10 } }
          },
          x: {
            grid: { display: false },
            ticks: { font: { size: 10 } }
          }
        }
      }
    });
  }

  private renderPieChart(data: StatsResponse): void {
    const ctx = document.getElementById('severityPieChart') as HTMLCanvasElement;
    if (!ctx) return;
    if (this.pieChart) this.pieChart.destroy();

    const counts: any = data.severity_counts || data.analysis_data?.severity_counts || {};
    const chartData = [
      Number(counts['high'] || counts['Critique'] || 0),
      Number(counts['medium'] || counts['Moyen'] || 0),
      Number(counts['low'] || counts['Faible'] || 0)
    ];

    this.pieChart = new Chart(ctx, {
      type: 'pie',
      data: {
        labels: ['Critique', 'Moyen', 'Faible'],
        datasets: [{
          data: chartData,
          backgroundColor: ['#ef4444', '#f59e0b', '#6366f1'],
          borderWidth: 2,
          borderColor: '#ffffff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11, weight: 'bold' } } }
        }
      }
    });
  }

  private renderTimeSeriesChart(data: StatsResponse): void {
    const ctx = document.getElementById('timeSeriesLineChart') as HTMLCanvasElement;
    if (!ctx) return;
    if (this.timeSeriesChart) this.timeSeriesChart.destroy();

    const labels = data.labels;
    
    this.timeSeriesChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [
          {
            label: 'Erreurs',
            data: data.critique,
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            fill: true,
            tension: 0.4,
            pointRadius: 3,
            pointHoverRadius: 5
          },
          {
            label: 'Avertissements',
            data: data.avertissement,
            borderColor: '#f59e0b',
            backgroundColor: 'rgba(245, 158, 11, 0.1)',
            fill: true,
            tension: 0.4,
            pointRadius: 3,
            pointHoverRadius: 5
          },
          {
            label: 'Infos',
            data: data.info,
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            fill: true,
            tension: 0.4,
            pointRadius: 3,
            pointHoverRadius: 5
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          intersect: false,
          mode: 'index'
        },
        plugins: {
          legend: {
            display: true,
            position: 'top',
            labels: { boxWidth: 12, font: { size: 10, weight: 'bold' } }
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(0,0,0,0.03)' },
            ticks: { font: { size: 10 } }
          },
          x: {
            grid: { display: false },
            ticks: { 
              font: { size: 9 },
              maxTicksLimit: 12,
              callback: function(value, index, values) {
                const label = this.getLabelForValue(value as number);
                if (label.length > 8) return label.substring(0, 8) + '...';
                return label;
              }
            }
          }
        }
      }
    });
  }
}
