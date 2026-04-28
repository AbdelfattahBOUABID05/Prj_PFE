import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { LogService, Notification } from '../../services/log.service';
import { NotificationService } from '../../services/notification.service';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [CommonModule, RouterModule],
  template: `
    <aside class="w-64 bg-slate-900 text-white flex flex-col h-screen fixed left-0 top-0 shadow-xl z-20">
      <!-- Section du logo -->
      <div class="p-6 border-b border-slate-800 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center shadow-indigo">
            <i class="fas fa-shield-alt text-lg"></i>
          </div>
          <div>
            <h1 class="font-black text-lg tracking-tighter italic uppercase">LOG<span class="text-indigo-500">SOC</span></h1>
            <p class="text-[8px] text-slate-500 font-bold uppercase tracking-widest">Security Ops</p>
          </div>
        </div>

        <!-- Notification Bell -->
        <div class="relative">
          <button (click)="toggleNotifications()" class="text-slate-500 hover:text-white transition relative">
            <i class="fas fa-bell text-xl"></i>
            <span *ngIf="unreadCount > 0" class="absolute -top-1 -right-1 bg-red-500 text-white text-[8px] font-bold px-1 rounded-full border border-slate-900 animate-pulse">
              {{ unreadCount }}
            </span>
          </button>

          <!-- Notification Dropdown -->
          <div *ngIf="showNotifications" class="absolute left-0 mt-4 w-72 bg-[#161b22] border border-white/10 rounded-2xl shadow-2xl z-50 overflow-hidden animate-fade-in">
            <div class="p-4 border-b border-white/5 flex justify-between items-center bg-slate-900/50">
              <h4 class="text-xs font-bold uppercase tracking-widest text-slate-400">Notifications</h4>
              <span class="text-[10px] text-indigo-400 font-bold">{{ unreadCount }} nouvelles</span>
            </div>
            <div class="max-h-96 overflow-y-auto">
              <div *ngFor="let n of notifications" 
                   (click)="onNotificationClick(n)"
                   [class]="'p-4 border-b border-white/5 hover:bg-white/5 transition cursor-pointer relative ' + (!n.is_read ? 'bg-indigo-500/5' : '')">
                <div *ngIf="!n.is_read" class="absolute left-0 top-0 bottom-0 w-1 bg-indigo-500"></div>
                <p class="text-[11px] font-bold text-white mb-1">{{ n.title }}</p>
                <p class="text-[10px] text-slate-400 line-clamp-2">{{ n.message }}</p>
                <p class="text-[8px] text-slate-500 mt-2 uppercase font-bold tracking-tighter">{{ n.created_at | date:'short' }}</p>
              </div>
              <div *ngIf="notifications.length === 0" class="p-8 text-center text-slate-500 italic text-xs">
                Aucune notification
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Menu de navigation -->
      <nav *ngIf="!isFirstLogin()" class="flex-1 p-4 space-y-2 overflow-y-auto">
        <p class="text-[10px] font-bold text-slate-500 uppercase tracking-widest px-4 mb-2">Analyseur</p>
        
        <a routerLink="/dashboard" routerLinkActive="bg-indigo-600 text-white shadow-indigo"
           class="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition group">
          <i class="fas fa-chart-line w-5 group-hover:scale-110 transition"></i>
          <span>Tableau de bord</span>
        </a>
        
        <a routerLink="/ssh" routerLinkActive="bg-indigo-600 text-white shadow-indigo"
           class="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition group">
          <i class="fas fa-server w-5 group-hover:scale-110 transition"></i>
          <span>Analyse SSH</span>
        </a>

        <a routerLink="/local-analysis" routerLinkActive="bg-indigo-600 text-white shadow-indigo"
           class="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition group">
          <i class="fas fa-file-upload w-5 group-hover:scale-110 transition"></i>
          <span>Analyse Locale</span>
        </a>

        <a routerLink="/history" routerLinkActive="bg-indigo-600 text-white shadow-indigo"
           class="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition group">
          <i class="fas fa-history w-5 group-hover:scale-110 transition"></i>
          <span>Historique</span>
        </a>

        <a routerLink="/jobs" routerLinkActive="bg-indigo-600 text-white shadow-indigo"
           class="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition group">
          <i class="fas fa-tasks w-5 group-hover:scale-110 transition"></i>
          <span>Mes Jobs</span>
        </a>

        <!-- Admin Only Menu -->
        <ng-container *ngIf="isAdmin()">
          <div class="mt-8 mb-2">
            <p class="text-[10px] font-bold text-slate-500 uppercase tracking-widest px-4">Administration</p>
          </div>

          <a routerLink="/admin/users" routerLinkActive="bg-indigo-600 text-white shadow-indigo"
             class="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition group">
            <i class="fas fa-users-cog w-5 group-hover:scale-110 transition"></i>
            <span>Gérer Utilisateurs</span>
          </a>

          <a routerLink="/admin/jobs" routerLinkActive="bg-indigo-600 text-white shadow-indigo"
             class="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition group">
            <i class="fas fa-clipboard-check w-5 group-hover:scale-110 transition"></i>
            <span>Valider Jobs</span>
          </a>

          <a routerLink="/admin/console" routerLinkActive="bg-indigo-600 text-white shadow-indigo"
             class="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition group">
            <i class="fas fa-terminal w-5 group-hover:scale-110 transition"></i>
            <span>Console Remote</span>
          </a>
        </ng-container>

        <div class="mt-8 mb-2">
          <p class="text-[10px] font-bold text-slate-500 uppercase tracking-widest px-4">Configuration</p>
        </div>

        <a routerLink="/profile" routerLinkActive="bg-indigo-600 text-white shadow-indigo"
           class="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition group">
          <i class="fas fa-user-circle w-5 group-hover:scale-110 transition"></i>
          <span>Mon Profil</span>
        </a>

        <a routerLink="/settings" routerLinkActive="bg-indigo-600 text-white shadow-indigo"
           class="flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white transition group">
          <i class="fas fa-cog w-5 group-hover:scale-110 transition"></i>
          <span>Paramètres</span>
        </a>
      </nav>

      <!-- Section profil -->
      <div class="p-4 border-t border-slate-700 bg-slate-800/50">
        <div class="flex items-center gap-3 mb-4">
          <div class="w-10 h-10 rounded-full bg-indigo-600 flex items-center justify-center shadow-indigo-lg border-2 border-slate-700">
            <i class="fas fa-user text-white"></i>
          </div>
          <div class="overflow-hidden text-ellipsis">
            <p class="text-sm font-bold text-white truncate">{{ fullName }}</p>
            <p class="text-[10px] font-bold text-indigo-400 uppercase tracking-wider">{{ roleLabel }}</p>
          </div>
        </div>
        
        <button (click)="logout()" 
                class="w-full flex items-center justify-center gap-2 px-4 py-2 bg-red-600/10 text-red-500 rounded-lg hover:bg-red-600 hover:text-white transition font-bold text-sm">
          <i class="fas fa-sign-out-alt"></i>
          <span>Déconnexion</span>
        </button>
      </div>
    </aside>
  `
})
export class SidebarComponent implements OnInit {
  username = '';
  fullName = '';
  roleLabel = '';
  notifications: Notification[] = [];
  unreadCount = 0;
  showNotifications = false;
  private refreshInterval: any;

  constructor(
    private authService: AuthService,
    private logService: LogService,
    private notify: NotificationService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.username = localStorage.getItem('username') || 'Utilisateur';
    const firstName = localStorage.getItem('firstName') || '';
    const lastName = localStorage.getItem('lastName') || '';
    this.fullName = [firstName, lastName].filter(Boolean).join(' ') || this.username;
    
    const role = localStorage.getItem('role') || 'Analyste';
    this.roleLabel = role === 'Admin' ? 'Administrateur' : 'Analyseur';
    
    if (!this.isFirstLogin()) {
      this.fetchNotifications();
      this.refreshInterval = setInterval(() => this.fetchNotifications(), 60000);
    }
  }

  isFirstLogin(): boolean {
    return this.authService.isFirstLogin();
  }

  ngOnDestroy(): void {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
    }
  }

  toggleNotifications(): void {
    this.showNotifications = !this.showNotifications;
  }

  fetchNotifications(): void {
    this.logService.getNotifications().subscribe({
      next: (res) => {
        this.notifications = res.notifications;
        this.unreadCount = this.notifications.filter(n => !n.is_read).length;
        
        const newCritical = this.notifications.find(n => !n.is_read && n.type === 'error');
        if (newCritical) {
          this.notify.warning('Alerte de sécurité critique détectée !', 'SOC Alert');
        }
      },
      error: () => {}
    });
  }

  onNotificationClick(notif: Notification): void {
    if (!notif.is_read) {
      this.logService.markNotificationAsRead(notif.id).subscribe({
        next: () => {
          notif.is_read = true;
          this.unreadCount = Math.max(0, this.unreadCount - 1);
        }
      });
    }
    if (notif.link) {
      this.router.navigate([notif.link]);
    }
    this.showNotifications = false;
  }

  async logout(): Promise<void> {
    const confirmed = await this.notify.confirm(
      'Déconnexion',
      'Voulez-vous vraiment quitter la session SOC ?',
      'question'
    );
    if (confirmed) {
      this.authService.logout().subscribe({
        next: () => {
          this.notify.success('Déconnexion réussie.');
          this.router.navigate(['/login']);
        },
        error: () => {
          this.router.navigate(['/login']);
        }
      });
    }
  }

  isAdmin(): boolean {
    return this.authService.isAdmin();
  }
}
