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
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
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
