import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule, Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { LogService, Notification } from '../../services/log.service';
import { NotificationService } from '../../services/notification.service';
import { ThemeService } from '../../services/theme.service';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';

@Component({
  selector: 'app-sidebar',
  standalone: true,
  imports: [CommonModule, RouterModule, MatSlideToggleModule],
  templateUrl: './sidebar.component.html',
  styleUrls: ['./sidebar.component.css']
})
export class SidebarComponent implements OnInit {
  notifications: Notification[] = [];
  unreadCount = 0;
  showNotifications = false;

  constructor(
    private authService: AuthService,
    private logService: LogService,
    private notify: NotificationService,
    private themeService: ThemeService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.loadNotifications();
    // Refresh notifications every minute
    setInterval(() => this.loadNotifications(), 60000);
  }

  isDark(): boolean {
    return this.themeService.isDark();
  }

  toggleTheme(): void {
    this.themeService.toggleTheme();
  }

  isAdmin(): boolean {
    return this.authService.isAdmin();
  }

  isFirstLogin(): boolean {
    return this.authService.isFirstLogin();
  }

  loadNotifications(): void {
    this.logService.getNotifications().subscribe({
      next: (res) => {
        this.notifications = res.notifications;
        this.unreadCount = this.notifications.filter(n => !n.is_read).length;
      }
    });
  }

  toggleNotifications(): void {
    this.showNotifications = !this.showNotifications;
  }

  onNotificationClick(notif: Notification): void {
    if (!notif.is_read) {
      this.logService.markNotificationAsRead(notif.id).subscribe(() => {
        notif.is_read = true;
        this.unreadCount = Math.max(0, this.unreadCount - 1);
      });
    }
    if (notif.link) {
      this.router.navigateByUrl(notif.link);
      this.showNotifications = false;
    }
  }

  logout(): void {
    this.authService.logout().subscribe({
      next: () => {
        this.router.navigate(['/login']);
      }
    });
  }
}
