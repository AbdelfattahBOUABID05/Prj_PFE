import { Component, OnInit, signal, computed } from '@angular/core';
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
    <div class="flex h-screen bg-[#0a0c10] text-slate-300">
      <app-sidebar></app-sidebar>

      <!-- Main Content -->
      <main class="flex-1 ml-64 overflow-auto p-8 relative">
        <!-- Background Decoration -->
        <div class="absolute top-0 right-0 w-[500px] h-[500px] bg-indigo-600/5 rounded-full blur-[120px] pointer-events-none"></div>

        <div class="max-w-7xl mx-auto">
          <!-- Header -->
          <header class="mb-8">
            <h2 class="text-3xl font-black text-white tracking-tight uppercase italic flex items-center gap-3">
              <i class="fas fa-history text-indigo-500 not-italic"></i>
              Historique <span class="text-indigo-500">SOC</span>
            </h2>
            <p class="text-slate-500 text-xs font-bold uppercase tracking-widest mt-1">Audit et traçabilité des analyses passées</p>
          </header>

          <!-- Search & Filters Bar -->
          <div class="bg-[#0d1117] border border-white/5 rounded-2xl p-4 mb-6 shadow-xl flex flex-wrap items-center gap-4">
            <!-- Search Bar -->
            <div class="flex-1 min-w-[300px] relative group">
              <div class="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 group-focus-within:text-indigo-500 transition-colors">
                <i class="fas fa-eye text-sm"></i>
              </div>
              <input 
                type="text" 
                [(ngModel)]="searchQuery" 
                (ngModelChange)="onSearchChange($event)"
                placeholder="Rechercher par serveur, fichier ou statut (ex: 192.168, auth.log, Critique)..."
                class="w-full bg-[#0a0c10] border border-white/10 rounded-xl py-3 pl-12 pr-4 text-sm text-white placeholder-slate-600 outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 transition-all"
              >
            </div>

            <!-- Date Filter -->
            <div class="flex items-center gap-3 bg-[#0a0c10] border border-white/10 rounded-xl px-4 py-2">
              <i class="fas fa-calendar-alt text-indigo-500 text-sm"></i>
              <input 
                type="date" 
                [(ngModel)]="filterDate" 
                (ngModelChange)="onDateChange($event)"
                class="bg-transparent border-none text-xs font-bold text-slate-400 outline-none uppercase"
              >
              <button 
                *ngIf="filterDate" 
                (click)="clearDateFilter()" 
                class="text-slate-600 hover:text-red-500 transition ml-2"
              >
                <i class="fas fa-times-circle"></i>
              </button>
            </div>

            <!-- Stats Badge -->
            <div class="px-4 py-2 bg-indigo-500/10 border border-indigo-500/20 rounded-xl">
              <span class="text-[10px] font-black text-indigo-400 uppercase tracking-widest">
                {{ filteredAnalyses().length }} Résultat(s)
              </span>
            </div>
          </div>

          <!-- Table Container -->
          <div class="bg-[#0d1117] border border-white/5 rounded-2xl shadow-2xl overflow-hidden">
            <div class="overflow-x-auto">
              <table class="w-full border-collapse">
                <thead>
                  <tr class="bg-white/5 border-b border-white/5">
                    <th class="px-6 py-4 text-left text-[10px] font-black text-slate-500 uppercase tracking-widest">Date / Heure</th>
                    <th class="px-6 py-4 text-left text-[10px] font-black text-slate-500 uppercase tracking-widest">Cible / Serveur</th>
                    <th class="px-6 py-4 text-left text-[10px] font-black text-slate-500 uppercase tracking-widest">Fichier</th>
                    <th class="px-6 py-4 text-left text-[10px] font-black text-slate-500 uppercase tracking-widest">Type</th>
                    <th class="px-6 py-4 text-left text-[10px] font-black text-slate-500 uppercase tracking-widest">Statut IA</th>
                    <th class="px-6 py-4 text-left text-[10px] font-black text-slate-500 uppercase tracking-widest">Score</th>
                    <th class="px-6 py-4 text-center text-[10px] font-black text-slate-500 uppercase tracking-widest">Actions</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-white/5">
                  <tr *ngFor="let analysis of filteredAnalyses()" class="hover:bg-white/[0.02] transition-colors group">
                    <td class="px-6 py-4 whitespace-nowrap">
                      <div class="text-xs font-bold text-slate-300">{{ formatDate(analysis.created_at).split(' ')[0] }}</div>
                      <div class="text-[10px] text-slate-500 font-medium">{{ formatDate(analysis.created_at).split(' ')[1] }}</div>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap">
                      <div class="flex items-center gap-2">
                        <div class="w-2 h-2 rounded-full" [ngClass]="analysis.server_ip ? 'bg-indigo-500' : 'bg-emerald-500'"></div>
                        <span class="text-xs font-black text-white uppercase">{{ analysis.server_ip || 'Local Machine' }}</span>
                      </div>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap">
                      <span class="text-[10px] font-mono text-slate-400 bg-white/5 px-2 py-1 rounded border border-white/5">
                        {{ analysis.file_path || 'N/A' }}
                      </span>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap">
                      <div class="flex items-center gap-2">
                        <i *ngIf="analysis.source_type === 'scheduled'" class="fas fa-clock text-indigo-400 text-[10px]" title="Analyse Planifiée"></i>
                        <span class="text-[9px] font-black uppercase tracking-tighter px-2 py-0.5 rounded border" 
                            [ngClass]="{
                              'text-indigo-400 border-indigo-500/20 bg-indigo-500/5': analysis.source_type === 'ssh',
                              'text-emerald-400 border-emerald-500/20 bg-emerald-500/5': analysis.source_type === 'upload',
                              'text-amber-400 border-amber-500/20 bg-amber-500/5': analysis.source_type === 'scheduled'
                            }">
                        {{ analysis.source_type === 'scheduled' ? 'Automatisé' : analysis.source_type }}
                      </span>
                    </div>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap">
                      <span [class]="getStatusClass(analysis.ai_status)">
                        {{ analysis.ai_status || 'N/A' }}
                      </span>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap">
                      <div class="flex items-center gap-2">
                        <div class="text-xs font-black text-white">{{ analysis.ai_score }}</div>
                        <div class="w-12 h-1 bg-white/5 rounded-full overflow-hidden">
                          <div class="h-full bg-indigo-500" [style.width.%]="analysis.ai_score"></div>
                        </div>
                      </div>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-center">
                      <div class="flex items-center justify-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button (click)="viewDetails(analysis)"
                                class="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 hover:bg-indigo-500 hover:text-white transition-all flex items-center justify-center"
                                title="Voir le rapport">
                          <i class="fas fa-external-link-alt text-xs"></i>
                        </button>
                        <button (click)="deleteAnalysis(analysis)"
                                class="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500 hover:text-white transition-all flex items-center justify-center"
                                title="Supprimer">
                          <i class="fas fa-trash-alt text-xs"></i>
                        </button>
                      </div>
                    </td>
                  </tr>
                  
                  <!-- Empty State -->
                  <tr *ngIf="filteredAnalyses().length === 0">
                    <td colspan="7" class="px-6 py-20 text-center">
                      <div class="flex flex-col items-center gap-4">
                        <div class="w-16 h-16 bg-white/5 rounded-full flex items-center justify-center text-slate-700">
                          <i class="fas fa-search text-3xl"></i>
                        </div>
                        <div>
                          <h3 class="text-white font-bold">Aucun résultat trouvé</h3>
                          <p class="text-xs text-slate-500 mt-1 uppercase tracking-widest">Essayez de modifier vos critères de recherche</p>
                        </div>
                        <button (click)="resetFilters()" class="text-indigo-400 text-[10px] font-black uppercase tracking-widest hover:text-indigo-300 transition mt-2">
                          Réinitialiser les filtres
                        </button>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </main>
    </div>
  `
})
export class LogHistoryComponent implements OnInit {
  // Signals pour une réactivité optimale (Angular 17)
  private allAnalyses = signal<Analysis[]>([]);
  searchQuery = signal<string>('');
  filterDate = signal<string>('');

  // Propriété calculée automatique
  filteredAnalyses = computed(() => {
    const query = this.searchQuery().toLowerCase().trim();
    const date = this.filterDate();
    const data = this.allAnalyses();

    return data.filter(a => {
      // Filtre par date
      if (date && a.created_at && !a.created_at.startsWith(date)) {
        return false;
      }

      // Filtre multi-critères
      if (!query) return true;

      const serverMatch = (a.server_ip || 'Local Machine').toLowerCase().includes(query);
      const fileMatch = (a.file_path || '').toLowerCase().includes(query);
      const statusMatch = (a.ai_status || '').toLowerCase().includes(query);
      const typeMatch = (a.source_type || '').toLowerCase().includes(query);

      return serverMatch || fileMatch || statusMatch || typeMatch;
    });
  });

  constructor(private logService: LogService) {}

  ngOnInit(): void {
    this.loadAnalyses();
  }

  loadAnalyses(): void {
    this.logService.getAnalyses().subscribe({
      next: (data) => {
        if (data.status === 'success') {
          const mapped = (data.analyses || []).map((analysis) => ({
            ...analysis,
            stats: analysis.stats || { errors: 0, warnings: 0, info: 0, total: 0 },
            ai_status: analysis.ai_status || 'Sain',
            ai_score: analysis.ai_score ?? 0,
            ai_menaces: analysis.ai_menaces ?? 0
          }));
          this.allAnalyses.set(mapped);
        }
      },
      error: (err) => console.error('Error loading analyses:', err)
    });
  }

  onSearchChange(value: string): void {
    this.searchQuery.set(value);
  }

  onDateChange(value: string): void {
    this.filterDate.set(value);
  }

  clearDateFilter(): void {
    this.filterDate.set('');
  }

  resetFilters(): void {
    this.searchQuery.set('');
    this.filterDate.set('');
  }

  formatDate(dateStr: string | null): string {
    if (!dateStr) return 'N/A N/A';
    const date = new Date(dateStr);
    return date.toLocaleString('fr-FR', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  getStatusClass(status: string | null): string {
    const base = 'px-2 py-0.5 rounded-full text-[9px] font-black uppercase tracking-tighter border ';
    if (!status) return base + 'bg-slate-500/10 text-slate-400 border-slate-500/20';
    
    const s = status.toLowerCase();
    if (s.includes('critique')) return base + 'bg-red-500/10 text-red-400 border-red-500/20';
    if (s.includes('attention') || s.includes('moyen')) return base + 'bg-amber-500/10 text-amber-400 border-amber-500/20';
    return base + 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
  }

  viewDetails(analysis: Analysis): void {
    window.location.href = `/report?id=${analysis.id}`;
  }

  deleteAnalysis(analysis: Analysis): void {
    if (confirm('Êtes-vous sûr de vouloir supprimer cette analyse ? Cette action est irréversible.')) {
      this.logService.deleteAnalysis(analysis.id).subscribe({
        next: () => this.loadAnalyses(),
        error: (err) => console.error('Error deleting analysis:', err)
      });
    }
  }
}
