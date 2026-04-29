import { Component, OnInit, signal, computed, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { LogService, Analysis } from '../../services/log.service';
import { SidebarComponent } from '../sidebar/sidebar.component';

@Component({
  selector: 'app-log-history',
  standalone: true,
  imports: [CommonModule, RouterModule, SidebarComponent, FormsModule],
  templateUrl: './log-history.component.html',
  styleUrls: ['./log-history.component.css']
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

  constructor(private logService: LogService, private cdr: ChangeDetectorRef) {}

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
          this.cdr.detectChanges();
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
    const base = 'px-3 py-1.5 rounded-xl text-[9px] font-black uppercase tracking-widest border transition-all duration-300 ';
    if (!status) return base + 'bg-slate-500/20 text-slate-400 border-slate-500/20';
    
    const s = status.toLowerCase();
    if (s.includes('critique') || s.includes('error')) return base + 'bg-rose-500/20 text-rose-400 border-rose-500/20';
    if (s.includes('attention') || s.includes('moyen') || s.includes('warning')) return base + 'bg-amber-500/20 text-amber-400 border-amber-500/20';
    return base + 'bg-emerald-500/20 text-emerald-400 border-emerald-500/20';
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
