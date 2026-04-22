import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { LogService, Analysis } from '../../services/log.service';
import { SidebarComponent } from '../sidebar/sidebar.component';

@Component({
  selector: 'app-log-history',
  standalone: true,
  imports: [CommonModule, RouterModule, SidebarComponent, FormsModule],
  template: `
    <div class="flex h-screen bg-slate-100">
      <app-sidebar></app-sidebar>

      <!-- Main Content -->
      <main class="flex-1 ml-64 overflow-auto p-8">
        <div class="stat-card">
          <div class="p-6 border-b border-slate-200 flex justify-between items-center">
            <h2 class="text-2xl font-bold text-slate-800">
              <i class="fas fa-history text-indigo-600 mr-2"></i>
              Historique des Analyses
            </h2>
            
            <div class="flex items-center gap-4 bg-slate-50 p-2 rounded-xl border border-slate-200">
              <span class="text-xs font-bold text-slate-500 uppercase px-2">Filtrer par date</span>
              <input type="date" [(ngModel)]="filterDate" (change)="applyFilter()"
                     class="bg-transparent border-none text-xs font-bold text-slate-600 outline-none">
              <button *ngIf="filterDate" (click)="clearFilter()" class="text-slate-400 hover:text-red-500 transition px-2">
                <i class="fas fa-times-circle"></i>
              </button>
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="w-full">
              <thead class="bg-slate-50">
                <tr>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase">Date</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase">Serveur</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase">Fichier</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase">Source</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase">Statut IA</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase">Score</th>
                  <th class="px-6 py-3 text-left text-xs font-medium text-slate-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-slate-200">
                <tr *ngFor="let analysis of analyses" class="hover:bg-slate-50">
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-slate-600">
                    {{ formatDate(analysis.created_at) }}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-slate-800">
                    {{ analysis.server_ip || 'Local' }}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-slate-500 italic font-mono text-[10px]">
                    {{ analysis.file_path || 'N/A' }}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm text-slate-600">
                    {{ analysis.source_type }}
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap">
                    <span [class]="getStatusClass(analysis.ai_status)">
                      {{ analysis.ai_status || 'N/A' }}
                    </span>
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-slate-800">
                    {{ analysis.ai_score }}/100
                  </td>
                  <td class="px-6 py-4 whitespace-nowrap text-sm">
                    <button (click)="viewDetails(analysis)"
                            class="text-indigo-600 hover:text-indigo-800 mr-3">
                      <i class="fas fa-eye"></i>
                    </button>
                    <button (click)="deleteAnalysis(analysis)"
                            class="text-red-600 hover:text-red-800">
                      <i class="fas fa-trash"></i>
                    </button>
                  </td>
                </tr>
                <tr *ngIf="analyses.length === 0">
                  <td colspan="6" class="px-6 py-8 text-center text-slate-500">
                    Aucune analyse trouvée.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  `
})
export class LogHistoryComponent implements OnInit {
  analyses: Analysis[] = [];
  allAnalyses: Analysis[] = [];
  filterDate: string = '';

  constructor(private logService: LogService) {}

  ngOnInit(): void {
    this.loadAnalyses();
  }

  loadAnalyses(): void {
    this.logService.getAnalyses().subscribe({
      next: (data) => {
        if (data.status === 'success') {
          this.allAnalyses = (data.analyses || []).map((analysis) => ({
            ...analysis,
            stats: analysis.stats || { errors: 0, warnings: 0, info: 0, total: 0 },
            ai_status: analysis.ai_status || 'N/A',
            ai_score: analysis.ai_score ?? 0,
            ai_menaces: analysis.ai_menaces ?? 0
          }));
          this.applyFilter();
        }
      },
      error: (err) => console.error('Error loading analyses:', err)
    });
  }

  applyFilter(): void {
    if (!this.filterDate) {
      this.analyses = [...this.allAnalyses];
      return;
    }
    this.analyses = this.allAnalyses.filter(a => {
      if (!a.created_at) return false;
      return a.created_at.startsWith(this.filterDate);
    });
  }

  clearFilter(): void {
    this.filterDate = '';
    this.applyFilter();
  }

  formatDate(dateStr: string | null): string {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleString();
  }

  getStatusClass(status: string | null): string {
    if (!status) return 'px-2 py-1 rounded-full text-xs bg-slate-100 text-slate-600';
    const s = status.toLowerCase();
    if (s.includes('critique')) return 'px-2 py-1 rounded-full text-xs bg-red-100 text-red-700';
    if (s.includes('attention')) return 'px-2 py-1 rounded-full text-xs bg-amber-100 text-amber-700';
    return 'px-2 py-1 rounded-full text-xs bg-emerald-100 text-emerald-700';
  }

  viewDetails(analysis: Analysis): void {
    window.location.href = `/report?id=${analysis.id}`;
  }

  deleteAnalysis(analysis: Analysis): void {
    if (confirm('Êtes-vous sûr de vouloir supprimer cette analyse ?')) {
      this.logService.deleteAnalysis(analysis.id).subscribe({
        next: () => this.loadAnalyses(),
        error: (err) => console.error('Error deleting analysis:', err)
      });
    }
  }
}
